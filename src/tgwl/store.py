"""
store.py — SQLite 存储层（逻辑白名单真相源）

两张表：
  admins  — 管理员列表（user_id, is_primary, added_by, added_at）
  entries — 白名单逻辑条目（id, type, value, label, added_by, added_at）

entry.type 枚举：
  "ip"       — 单 IPv4 地址（标准化为 x.x.x.x）
  "cidr"     — IPv4 CIDR 段（标准化为 network address/prefix）
  "province" — 省级（value = 行政区划码字符串，如 "330000"）
  "city"     — 市级（value = 行政区划码字符串，如 "330100"）

注意：不存原始省市名字符串——用行政区划码，避免同名/简写歧义；
label 字段存人类可读名称（"浙江省"、"杭州市"）供展示。
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Literal, Optional

# 条目类型字面量
EntryType = Literal["ip", "cidr", "province", "city"]

VALID_ENTRY_TYPES: frozenset[str] = frozenset({"ip", "cidr", "province", "city"})


# --------------------------------------------------------------------------- #
# 数据类                                                                        #
# --------------------------------------------------------------------------- #

@dataclass
class Admin:
    user_id: int
    is_primary: bool
    added_by: int          # 谁添加的（primary_admin 首次写入时 added_by = self）
    added_at: datetime


@dataclass
class Entry:
    id: int
    type: EntryType
    value: str             # 标准化值
    label: str             # 人类可读标签（展示用）
    added_by: int
    added_at: datetime


# --------------------------------------------------------------------------- #
# Schema                                                                        #
# --------------------------------------------------------------------------- #

_SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS admins (
    user_id    INTEGER PRIMARY KEY,
    is_primary INTEGER NOT NULL DEFAULT 0,   -- 1 = 主管理员
    added_by   INTEGER NOT NULL,
    added_at   TEXT    NOT NULL              -- ISO-8601 UTC
);

CREATE TABLE IF NOT EXISTS entries (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    type       TEXT    NOT NULL,             -- ip | cidr | province | city
    value      TEXT    NOT NULL,             -- 标准化值（行政区划码 / CIDR / IP）
    label      TEXT    NOT NULL DEFAULT '',  -- 人类可读（"浙江省"/"1.2.3.4"）
    added_by   INTEGER NOT NULL,
    added_at   TEXT    NOT NULL,             -- ISO-8601 UTC
    UNIQUE(type, value)                      -- 同类型同值只存一条
);

CREATE INDEX IF NOT EXISTS idx_entries_type ON entries(type);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


# --------------------------------------------------------------------------- #
# Store                                                                         #
# --------------------------------------------------------------------------- #

class Store:
    """线程安全的 SQLite 存储，使用 WAL 模式与连接池（每线程一个连接）。"""

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        # 初始化 schema（使用独立连接，确保建表完成后才返回）
        with self._connect() as conn:
            conn.executescript(_SCHEMA_SQL)

    # ------------------------------------------------------------------ #
    # 连接管理                                                             #
    # ------------------------------------------------------------------ #

    def _get_conn(self) -> sqlite3.Connection:
        """获取当前线程的连接（按需创建）。"""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(
                self._db_path,
                check_same_thread=False,
                detect_types=sqlite3.PARSE_DECLTYPES,
            )
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return self._local.conn

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        """上下文管理器，自动 commit / rollback。"""
        conn = self._get_conn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def close(self) -> None:
        """关闭当前线程的连接。"""
        conn = getattr(self._local, "conn", None)
        if conn:
            conn.close()
            self._local.conn = None

    # ------------------------------------------------------------------ #
    # 工具                                                                 #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _now_utc() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _row_to_admin(row: sqlite3.Row) -> Admin:
        return Admin(
            user_id=row["user_id"],
            is_primary=bool(row["is_primary"]),
            added_by=row["added_by"],
            added_at=datetime.fromisoformat(row["added_at"]),
        )

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> Entry:
        return Entry(
            id=row["id"],
            type=row["type"],
            value=row["value"],
            label=row["label"],
            added_by=row["added_by"],
            added_at=datetime.fromisoformat(row["added_at"]),
        )

    # ------------------------------------------------------------------ #
    # 管理员 API                                                           #
    # ------------------------------------------------------------------ #

    def ensure_primary_admin(self, user_id: int) -> None:
        """首次启动时写入主管理员（已存在则忽略，且不降级为非 primary）。"""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO admins (user_id, is_primary, added_by, added_at)
                VALUES (?, 1, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET is_primary = 1
                """,
                (user_id, user_id, self._now_utc()),
            )

    def add_admin(self, user_id: int, added_by: int) -> bool:
        """添加普通管理员。已存在返回 False，新增返回 True。"""
        with self._connect() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO admins (user_id, is_primary, added_by, added_at)
                    VALUES (?, 0, ?, ?)
                    """,
                    (user_id, added_by, self._now_utc()),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def remove_admin(self, user_id: int) -> bool:
        """删除管理员（不允许删除主管理员）。成功返回 True。"""
        with self._connect() as conn:
            # 先检查是否是主管理员
            row = conn.execute(
                "SELECT is_primary FROM admins WHERE user_id = ?", (user_id,)
            ).fetchone()
            if row is None:
                return False  # 不存在
            if row["is_primary"]:
                raise PermissionError(f"不能删除主管理员 {user_id}")
            conn.execute("DELETE FROM admins WHERE user_id = ?", (user_id,))
            return True

    def get_admin(self, user_id: int) -> Optional[Admin]:
        """查询单个管理员，不存在返回 None。"""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM admins WHERE user_id = ?", (user_id,)
            ).fetchone()
        return self._row_to_admin(row) if row else None

    def is_admin(self, user_id: int) -> bool:
        """判断是否是管理员（含主管理员）。"""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM admins WHERE user_id = ?", (user_id,)
            ).fetchone()
        return row is not None

    def is_primary_admin(self, user_id: int) -> bool:
        """判断是否是主管理员。"""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM admins WHERE user_id = ? AND is_primary = 1", (user_id,)
            ).fetchone()
        return row is not None

    def list_admins(self) -> list[Admin]:
        """列出所有管理员，主管理员排在最前。"""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM admins ORDER BY is_primary DESC, added_at ASC"
            ).fetchall()
        return [self._row_to_admin(r) for r in rows]

    # ------------------------------------------------------------------ #
    # 白名单条目 API                                                       #
    # ------------------------------------------------------------------ #

    def add_entry(
        self,
        entry_type: EntryType,
        value: str,
        label: str,
        added_by: int,
    ) -> Optional[Entry]:
        """
        添加白名单条目。
        若同类型同值已存在（UNIQUE 约束），返回 None（幂等）。
        成功返回新建 Entry。
        """
        if entry_type not in VALID_ENTRY_TYPES:
            raise ValueError(f"非法 entry type: {entry_type!r}")
        with self._connect() as conn:
            try:
                cursor = conn.execute(
                    """
                    INSERT INTO entries (type, value, label, added_by, added_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (entry_type, value, label, added_by, self._now_utc()),
                )
                row_id = cursor.lastrowid
            except sqlite3.IntegrityError:
                return None  # 已存在
        return self.get_entry(row_id)  # type: ignore[arg-type]

    def remove_entry(self, entry_id: int) -> bool:
        """删除条目。成功返回 True，不存在返回 False。"""
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
        return cursor.rowcount > 0

    def get_entry(self, entry_id: int) -> Optional[Entry]:
        """按 ID 查询条目。"""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM entries WHERE id = ?", (entry_id,)
            ).fetchone()
        return self._row_to_entry(row) if row else None

    def list_entries(
        self, entry_type: Optional[EntryType] = None
    ) -> list[Entry]:
        """列出所有条目，可按类型过滤。"""
        with self._connect() as conn:
            if entry_type is not None:
                rows = conn.execute(
                    "SELECT * FROM entries WHERE type = ? ORDER BY added_at ASC",
                    (entry_type,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM entries ORDER BY type ASC, added_at ASC"
                ).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def list_entries_paged(
        self,
        entry_type: Optional[EntryType] = None,
        page: int = 0,
        page_size: int = 10,
    ) -> tuple[list[Entry], int]:
        """
        分页查询条目。
        返回 (条目列表, 总条目数)。
        """
        offset = page * page_size
        with self._connect() as conn:
            if entry_type is not None:
                total = conn.execute(
                    "SELECT COUNT(*) FROM entries WHERE type = ?", (entry_type,)
                ).fetchone()[0]
                rows = conn.execute(
                    "SELECT * FROM entries WHERE type = ? ORDER BY added_at ASC LIMIT ? OFFSET ?",
                    (entry_type, page_size, offset),
                ).fetchall()
            else:
                total = conn.execute(
                    "SELECT COUNT(*) FROM entries"
                ).fetchone()[0]
                rows = conn.execute(
                    "SELECT * FROM entries ORDER BY type ASC, added_at ASC LIMIT ? OFFSET ?",
                    (page_size, offset),
                ).fetchall()
        return [self._row_to_entry(r) for r in rows], total

    def count_entries(self) -> dict[str, int]:
        """返回各类型条目计数及总数。"""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT type, COUNT(*) as cnt FROM entries GROUP BY type"
            ).fetchall()
            total = conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
        counts: dict[str, int] = {r["type"]: r["cnt"] for r in rows}
        counts["total"] = total
        return counts

    def entry_exists(self, entry_type: EntryType, value: str) -> bool:
        """判断同类型同值条目是否已存在。"""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM entries WHERE type = ? AND value = ?",
                (entry_type, value),
            ).fetchone()
        return row is not None

    # ------------------------------------------------------------------ #
    # reconcile 所需：获取全量逻辑条目                                    #
    # ------------------------------------------------------------------ #

    def get_all_geo_entries(self) -> list[Entry]:
        """返回全部省市条目（type in province/city），供 geo.py 展开。"""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM entries WHERE type IN ('province', 'city') ORDER BY added_at ASC"
            ).fetchall()
        return [self._row_to_entry(r) for r in rows]

    # ------------------------------------------------------------------ #
    # 设置 API                                                            #
    # ------------------------------------------------------------------ #

    def get_setting(self, key: str) -> str | None:
        """查询设置项，不存在返回 None。"""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM settings WHERE key = ?", (key,)
            ).fetchone()
        return row["value"] if row else None

    def set_setting(self, key: str, value: str) -> None:
        """写入或更新设置项（UPSERT）。"""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO settings (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, value),
            )

    def get_all_ip_entries(self) -> list[Entry]:
        """返回全部 IP/CIDR 条目（type in ip/cidr），供 firewall.py 直接使用。"""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM entries WHERE type IN ('ip', 'cidr') ORDER BY added_at ASC"
            ).fetchall()
        return [self._row_to_entry(r) for r in rows]
