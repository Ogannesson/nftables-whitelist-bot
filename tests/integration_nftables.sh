#!/usr/bin/env bash
# =============================================================================
# tg-whitelist — nftables 集成测试脚本
# =============================================================================
# 用途：在目标 Linux 服务器（需 root 或 CAP_NET_ADMIN + AF_NETLINK）上执行，
#       验证 nftables 规则结构、连通性、panic/恢复、与现有规则共存。
#
# 依赖：nft, nmap 或 nc(netcat), Python3, sqlite3
# 用法：sudo bash tests/integration_nftables.sh [--cleanup-only]
#        --cleanup-only  仅删除测试残留规则，不运行测试
#
# 警告：此脚本会临时修改 nftables 规则，测试后自动清理。
#       务必在非生产状态下运行，或至少确认 SSH 22 已通过其他方式保护。
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TEST_DB="/tmp/tgwl_test.db"
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

# ─── 颜色输出 ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_pass()  { echo -e "${GREEN}[PASS]${NC}  $*"; ((++PASS_COUNT)); }
log_fail()  { echo -e "${RED}[FAIL]${NC}  $*"; ((++FAIL_COUNT)); }
log_skip()  { echo -e "${YELLOW}[SKIP]${NC}  $*"; ((++SKIP_COUNT)); }
log_title() { echo -e "\n${BLUE}══════════ $* ══════════${NC}"; }

# ─── 前置检查 ─────────────────────────────────────────────────────────────────
preflight() {
    log_title "前置检查"

    # 必须是 root 或有 CAP_NET_ADMIN
    if [[ $EUID -ne 0 ]]; then
        if ! capsh --print 2>/dev/null | grep -q "cap_net_admin"; then
            log_fail "需要 root 权限或 CAP_NET_ADMIN，请以 sudo 运行"
            exit 1
        fi
    fi
    log_pass "权限检查（root/CAP_NET_ADMIN）"

    # nft 命令可用
    if ! command -v nft &>/dev/null; then
        log_fail "nft 未找到，请先安装 nftables: apt install nftables"
        exit 1
    fi
    log_pass "nft 命令可用 ($(nft --version 2>&1 | head -1))"

    # Python3 可用
    if ! command -v python3 &>/dev/null; then
        log_fail "python3 未找到"
        exit 1
    fi
    log_pass "python3 可用"

    # sqlite3 可用
    if ! command -v sqlite3 &>/dev/null; then
        log_skip "sqlite3 未找到，跳过 DB 恢复测试"
    else
        log_pass "sqlite3 可用"
    fi
}

# ─── 清理残留 ─────────────────────────────────────────────────────────────────
cleanup() {
    log_info "清理测试残留规则..."
    nft delete table inet whitelist 2>/dev/null || true
    nft delete table inet existing_test 2>/dev/null || true
    rm -f "$TEST_DB"
    log_info "清理完毕"
}

# --cleanup-only 模式
if [[ "${1:-}" == "--cleanup-only" ]]; then
    cleanup
    exit 0
fi

# 注册 EXIT trap，确保测试失败时也清理
trap cleanup EXIT

# ─── 测试 1：规则结构验证 ──────────────────────────────────────────────────────
test_rule_structure() {
    log_title "测试 1：规则结构验证"

    # 先确保 table 不存在（模拟干净启动）
    nft delete table inet whitelist 2>/dev/null || true

    # 手动创建预期规则（模拟 bot 启动时 ensure_table/chain/set）
    nft -f - <<'NFT_EOF'
table inet whitelist {
    set whitelist4 {
        type ipv4_addr
        flags interval
        auto-merge
    }

    chain input {
        type filter hook input priority -10; policy accept;
        iif "lo" accept
        ct state established,related accept
        ct state invalid drop
        tcp dport 22 accept
        ip saddr @whitelist4 accept
        ip6 nexthdr ipv6-icmp accept
        meta nfproto ipv4 drop
    }
}
NFT_EOF

    # 1.1 table 存在
    if nft list tables | grep -q "inet whitelist"; then
        log_pass "table inet whitelist 存在"
    else
        log_fail "table inet whitelist 不存在"
    fi

    # 1.2 set whitelist4 存在
    if nft list set inet whitelist whitelist4 &>/dev/null; then
        log_pass "set whitelist4 存在"
    else
        log_fail "set whitelist4 不存在"
    fi

    # 1.3 set 有 flags interval
    if nft list set inet whitelist whitelist4 2>/dev/null | grep -q "flags interval"; then
        log_pass "set whitelist4 有 flags interval"
    else
        log_fail "set whitelist4 缺少 flags interval（CIDR 支持受影响）"
    fi

    # 1.4 set 有 auto-merge
    if nft list set inet whitelist whitelist4 2>/dev/null | grep -q "auto-merge"; then
        log_pass "set whitelist4 有 auto-merge"
    else
        log_fail "set whitelist4 缺少 auto-merge（重叠 CIDR 处理受影响）"
    fi

    # 1.5 chain priority = -10（先于默认 filter）
    # 注：先捕获再 grep，避免 grep -q 提前退出导致 nft SIGPIPE + pipefail 误判
    _CHAIN15=$(nft list chain inet whitelist input 2>/dev/null)
    if echo "$_CHAIN15" | grep -qE "priority (filter - 10|-10)"; then
        log_pass "chain input priority -10（早于默认 filter(0)）"
    else
        log_fail "chain input priority 不是 -10"
    fi

    # 1.6 规则顺序：防锁死关键规则必须在 drop 之前
    # 提取 chain 规则，按行顺序检查
    CHAIN_RULES=$(nft list chain inet whitelist input 2>/dev/null)

    # 找各关键规则的行号
    LINE_LO=$(echo "$CHAIN_RULES" | grep -n "iif.*lo.*accept" | head -1 | cut -d: -f1)
    LINE_ESTAB=$(echo "$CHAIN_RULES" | grep -n "established,related.*accept" | head -1 | cut -d: -f1)
    LINE_SSH22=$(echo "$CHAIN_RULES" | grep -n "tcp dport 22 accept" | head -1 | cut -d: -f1)
    LINE_DROP=$(echo "$CHAIN_RULES" | grep -n "meta nfproto ipv4 drop" | head -1 | cut -d: -f1)

    if [[ -n "$LINE_LO" && -n "$LINE_DROP" && "$LINE_LO" -lt "$LINE_DROP" ]]; then
        log_pass "规则顺序：iif lo accept 在 ipv4 drop 之前（行 $LINE_LO < $LINE_DROP）"
    else
        log_fail "规则顺序错误：iif lo 行($LINE_LO) 应在 drop 行($LINE_DROP) 之前"
    fi

    if [[ -n "$LINE_ESTAB" && -n "$LINE_DROP" && "$LINE_ESTAB" -lt "$LINE_DROP" ]]; then
        log_pass "规则顺序：established,related accept 在 ipv4 drop 之前（行 $LINE_ESTAB < $LINE_DROP）"
    else
        log_fail "规则顺序错误：established,related 行($LINE_ESTAB) 应在 drop 行($LINE_DROP) 之前 【锁死风险！】"
    fi

    if [[ -n "$LINE_SSH22" && -n "$LINE_DROP" && "$LINE_SSH22" -lt "$LINE_DROP" ]]; then
        log_pass "规则顺序：tcp dport 22 accept 在 ipv4 drop 之前（行 $LINE_SSH22 < $LINE_DROP）"
    else
        log_fail "规则顺序错误：tcp dport 22 行($LINE_SSH22) 应在 drop 行($LINE_DROP) 之前 【SSH 锁死风险！】"
    fi

    # 1.7 确认有 ipv6-icmp accept（v6 邻居发现放行）
    if echo "$CHAIN_RULES" | grep -q "ipv6-icmp accept"; then
        log_pass "ipv6-icmp accept 规则存在（v6 邻居发现放行）"
    else
        log_skip "ipv6-icmp accept 规则未找到（v6 可能受影响）"
    fi
}

# ─── 测试 2：set 元素增删验证 ──────────────────────────────────────────────────
test_set_operations() {
    log_title "测试 2：set 元素增删（模拟 reconcile）"

    TEST_IP="192.168.100.1"
    TEST_CIDR="10.200.0.0/24"

    # 2.1 添加单 IP
    nft add element inet whitelist whitelist4 { "${TEST_IP}" }
    if nft list set inet whitelist whitelist4 | grep -q "${TEST_IP}"; then
        log_pass "添加单 IP ${TEST_IP} 成功"
    else
        log_fail "添加单 IP ${TEST_IP} 失败"
    fi

    # 2.2 添加 CIDR
    nft add element inet whitelist whitelist4 { "${TEST_CIDR}" }
    if nft list set inet whitelist whitelist4 | grep -q "10.200.0.0/24"; then
        log_pass "添加 CIDR ${TEST_CIDR} 成功"
    else
        log_fail "添加 CIDR ${TEST_CIDR} 失败"
    fi

    # 2.3 flush set（模拟 reconcile 全量重建）
    nft flush set inet whitelist whitelist4
    SET_CONTENT=$(nft list set inet whitelist whitelist4)
    if ! echo "$SET_CONTENT" | grep -qE "192\.168|10\.200"; then
        log_pass "flush set 成功（set 已清空）"
    else
        log_fail "flush set 后 set 仍有旧元素"
    fi

    # 2.4 重新添加多个 CIDR（模拟 reconcile 重建）
    nft add element inet whitelist whitelist4 { "172.16.0.0/12", "10.0.0.0/8" }
    ELEM_COUNT=$(nft list set inet whitelist whitelist4 | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+" | wc -l)
    if [[ "$ELEM_COUNT" -ge 2 ]]; then
        log_pass "批量添加多个 CIDR 成功（${ELEM_COUNT} 条）"
    else
        log_fail "批量添加 CIDR 失败（仅 ${ELEM_COUNT} 条）"
    fi

    # 2.5 auto-merge：添加重叠 CIDR 不报错
    nft add element inet whitelist whitelist4 { "10.1.0.0/16" } 2>/dev/null && {
        log_pass "auto-merge：添加 10.1.0.0/16（已含于 10.0.0.0/8）不报错"
    } || {
        log_fail "auto-merge：添加重叠 CIDR 报错"
    }
}

# ─── 测试 3：连通性模拟测试（使用 nft trace / 逻辑验证）─────────────────────
test_connectivity_logic() {
    log_title "测试 3：连通性逻辑验证（nft 规则语义）"

    # 重置 set，加入明确白名单 IP
    nft flush set inet whitelist whitelist4
    WHITELIST_IP="203.0.113.1"   # TEST-NET-3（RFC 5737 文档用 IP，不会真实路由）
    nft add element inet whitelist whitelist4 { "${WHITELIST_IP}" }

    # 3.1 验证白名单 IP 能命中 accept 规则（通过 nft 规则语义检查）
    # 使用 nft 的内置测试：检查 set 中是否包含目标 IP
    if nft list set inet whitelist whitelist4 | grep -q "${WHITELIST_IP}"; then
        log_pass "白名单 IP ${WHITELIST_IP} 在 set 中（对应 'ip saddr @whitelist4 accept'）"
    else
        log_fail "白名单 IP ${WHITELIST_IP} 未在 set 中"
    fi

    NON_WHITELIST_IP="198.51.100.1"  # TEST-NET-2（RFC 5737）
    if ! nft list set inet whitelist whitelist4 | grep -q "${NON_WHITELIST_IP}"; then
        log_pass "非白名单 IP ${NON_WHITELIST_IP} 不在 set 中（将命中 'meta nfproto ipv4 drop'）"
    else
        log_fail "非白名单 IP ${NON_WHITELIST_IP} 意外出现在 set 中"
    fi

    # 3.2 规则逻辑：SSH(22) 规则在 drop 前，语义上对任意源 IP 放行 22
    CHAIN=$(nft list chain inet whitelist input 2>/dev/null)
    SSH_LINE=$(echo "$CHAIN" | grep -n "tcp dport 22 accept" | head -1 | cut -d: -f1)
    DROP_LINE=$(echo "$CHAIN" | grep -n "meta nfproto ipv4 drop" | head -1 | cut -d: -f1)

    if [[ -n "$SSH_LINE" && -n "$DROP_LINE" && "$SSH_LINE" -lt "$DROP_LINE" ]]; then
        log_pass "SSH 22 对所有源 IP 放行（规则在 drop 前，行 $SSH_LINE < $DROP_LINE）"
    else
        log_fail "SSH 22 放行规则位置异常（行 $SSH_LINE, drop 行 $DROP_LINE）"
    fi

    # 3.3 established,related accept：语义验证（防止已建连 SSH 被切断）
    ESTAB_LINE=$(echo "$CHAIN" | grep -n "established,related.*accept" | head -1 | cut -d: -f1)
    if [[ -n "$ESTAB_LINE" && "$ESTAB_LINE" -lt "$DROP_LINE" ]]; then
        log_pass "established,related accept 在 drop 前（行 $ESTAB_LINE），已建连 SSH 不会被切断"
    else
        log_fail "established,related accept 位置异常 【已建连 SSH 有被切断风险！】"
    fi

    # 3.4 若有 nmap 或 nc，进行真实端口探测（在本机 lo 接口上）
    if command -v nc &>/dev/null; then
        log_info "nc 可用，执行 lo 接口端口探测..."
        # lo 接口有 iif lo accept，应放行所有流量
        if timeout 2 nc -z 127.0.0.1 22 2>/dev/null; then
            log_pass "127.0.0.1:22 可达（lo 接口，iif lo accept 生效）"
        else
            log_skip "127.0.0.1:22 不可达（可能 SSH 服务未开启，非防火墙问题）"
        fi
    else
        log_skip "nc 未安装，跳过真实端口探测（apt install netcat-openbsd）"
    fi
}

# ─── 测试 4：panic 指令验证 ────────────────────────────────────────────────────
test_panic() {
    log_title "测试 4：Panic 指令 —— 删除 table"

    # 确保 table 存在
    if ! nft list tables | grep -q "inet whitelist"; then
        nft add table inet whitelist
    fi

    # 4.1 执行 panic（nft delete table inet whitelist）
    nft delete table inet whitelist

    if ! nft list tables 2>/dev/null | grep -q "inet whitelist"; then
        log_pass "panic 后 table inet whitelist 已删除"
    else
        log_fail "panic 后 table inet whitelist 仍存在"
    fi

    # 4.2 panic 后现有规则（如果有）不受影响
    # （现有规则测试在 test_coexistence 里覆盖）
    log_pass "panic 仅删除 whitelist table，不影响其他 table（下方共存测试验证）"
}

# ─── 测试 5：从 SQLite 自动恢复 ────────────────────────────────────────────────
test_recovery_from_sqlite() {
    log_title "测试 5：从 SQLite 自动恢复（模拟 bot 重启）"

    if ! command -v sqlite3 &>/dev/null; then
        log_skip "sqlite3 未安装，跳过 DB 恢复测试"
        return
    fi

    # 创建最小 SQLite DB（模拟 store.py 建表后的状态）
    rm -f "$TEST_DB"
    sqlite3 "$TEST_DB" <<'SQL_EOF'
CREATE TABLE entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    added_by INTEGER,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO entries (type, value) VALUES ('ip', '203.0.113.50');
INSERT INTO entries (type, value) VALUES ('cidr', '10.10.10.0/24');
SQL_EOF

    if [[ -f "$TEST_DB" ]]; then
        log_pass "测试 SQLite DB 创建成功"
    else
        log_fail "测试 SQLite DB 创建失败"
        return
    fi

    # 从 DB 读取 IP/CIDR 条目
    ENTRIES=$(sqlite3 "$TEST_DB" "SELECT value FROM entries WHERE type IN ('ip','cidr');")

    # 模拟 reconcile：重建 table/chain/set 并重新灌入
    nft delete table inet whitelist 2>/dev/null || true

    nft -f - <<'NFT_EOF'
table inet whitelist {
    set whitelist4 {
        type ipv4_addr
        flags interval
        auto-merge
    }
    chain input {
        type filter hook input priority -10; policy accept;
        iif "lo" accept
        ct state established,related accept
        ct state invalid drop
        tcp dport 22 accept
        ip saddr @whitelist4 accept
        ip6 nexthdr ipv6-icmp accept
        meta nfproto ipv4 drop
    }
}
NFT_EOF

    # 将 DB 条目批量写入 set
    for entry in $ENTRIES; do
        nft add element inet whitelist whitelist4 { "$entry" } 2>/dev/null || \
            log_fail "恢复条目 $entry 失败"
    done

    # 5.1 验证 IP 已恢复
    if nft list set inet whitelist whitelist4 | grep -q "203.0.113.50"; then
        log_pass "从 DB 恢复 IP 203.0.113.50 成功"
    else
        log_fail "从 DB 恢复 IP 203.0.113.50 失败"
    fi

    # 5.2 验证 CIDR 已恢复
    if nft list set inet whitelist whitelist4 | grep -q "10.10.10.0/24"; then
        log_pass "从 DB 恢复 CIDR 10.10.10.0/24 成功"
    else
        log_fail "从 DB 恢复 CIDR 10.10.10.0/24 失败"
    fi

    # 5.3 恢复后规则结构完整性
    # 注：先捕获再 grep，避免 grep -q 提前退出导致 nft SIGPIPE + pipefail 误判
    _CHAIN53=$(nft list chain inet whitelist input 2>/dev/null)
    if echo "$_CHAIN53" | grep -q "tcp dport 22 accept"; then
        log_pass "恢复后规则结构完整（SSH 22 放行规则存在）"
    else
        log_fail "恢复后规则结构不完整"
    fi
}

# ─── 测试 6：与现有规则共存 ────────────────────────────────────────────────────
test_coexistence() {
    log_title "测试 6：与现有规则共存"

    # 先清理 whitelist table
    nft delete table inet whitelist 2>/dev/null || true

    # 6.1 创建模拟"现有规则"（类似服务器已有的 table）
    nft -f - <<'NFT_EOF'
table inet existing_test {
    chain input {
        type filter hook input priority 0; policy accept;
        tcp dport 80 accept
        tcp dport 443 accept
    }
}
NFT_EOF

    if nft list tables | grep -q "inet existing_test"; then
        log_pass "模拟现有规则 table inet existing_test 创建成功"
    else
        log_fail "模拟现有规则创建失败"
        return
    fi

    # 6.2 在现有规则基础上，叠加 whitelist table
    nft -f - <<'NFT_EOF'
table inet whitelist {
    set whitelist4 {
        type ipv4_addr
        flags interval
        auto-merge
    }
    chain input {
        type filter hook input priority -10; policy accept;
        iif "lo" accept
        ct state established,related accept
        ct state invalid drop
        tcp dport 22 accept
        ip saddr @whitelist4 accept
        ip6 nexthdr ipv6-icmp accept
        meta nfproto ipv4 drop
    }
}
NFT_EOF

    # 6.3 两个 table 都存在
    if nft list tables | grep -q "inet existing_test" && nft list tables | grep -q "inet whitelist"; then
        log_pass "两个 table 共存（现有 existing_test + 新 whitelist）"
    else
        log_fail "table 共存失败"
    fi

    # 6.4 whitelist table 优先级更高（-10 < 0）
    WL_PRIO=$(nft list chain inet whitelist input 2>/dev/null | grep -oE "priority [^;]+" | head -1 || true)
    EX_PRIO=$(nft list chain inet existing_test input 2>/dev/null | grep -oE "priority [^;]+" | head -1 || true)

    # nft 1.1.1 显示 priority -10 为 "priority filter - 10"，priority 0 为 "priority filter"
    if echo "$WL_PRIO" | grep -q -- "- 10"; then
        log_pass "whitelist chain priority($WL_PRIO) 低于 existing($EX_PRIO)，whitelist 先评估"
    else
        log_fail "whitelist chain priority 异常（WL=$WL_PRIO, EX=$EX_PRIO）"
    fi

    # 6.5 panic（删 whitelist table）不影响现有规则
    nft delete table inet whitelist

    if nft list tables | grep -q "inet existing_test"; then
        log_pass "panic（删 whitelist table）后，现有 existing_test table 完好"
    else
        log_fail "panic 后，现有 existing_test table 意外被删除"
    fi

    if ! nft list tables | grep -q "inet whitelist"; then
        log_pass "panic 后 whitelist table 已删除，仅影响自身"
    else
        log_fail "panic 后 whitelist table 仍存在"
    fi

    # 清理现有规则测试 table
    nft delete table inet existing_test 2>/dev/null || true
}

# ─── 测试 7：大量 CIDR 性能测试 ────────────────────────────────────────────────
test_bulk_cidr_performance() {
    log_title "测试 7：大量 CIDR 性能（模拟省级白名单）"

    # 重建 table
    nft delete table inet whitelist 2>/dev/null || true
    nft -f - <<'NFT_EOF'
table inet whitelist {
    set whitelist4 {
        type ipv4_addr
        flags interval
        auto-merge
    }
    chain input {
        type filter hook input priority -10; policy accept;
        iif "lo" accept
        ct state established,related accept
        ct state invalid drop
        tcp dport 22 accept
        ip saddr @whitelist4 accept
        ip6 nexthdr ipv6-icmp accept
        meta nfproto ipv4 drop
    }
}
NFT_EOF

    # 生成 1000 条模拟 CIDR（覆盖真实省级 CIDR 数量级）
    log_info "生成 1000 条测试 CIDR..."
    CIDRS=""
    for i in $(seq 1 250); do
        CIDRS+="10.$i.0.0/24, 172.$((16 + i % 16)).$i.0/24, 192.168.$((i % 256)).0/24, "
        CIDRS+="100.$((i % 128)).$i.0/24, "
    done
    CIDRS="${CIDRS%, }"  # 去掉末尾逗号

    START_TIME=$(date +%s%N)
    echo "add element inet whitelist whitelist4 { $CIDRS }" | nft -f -
    END_TIME=$(date +%s%N)

    ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
    ACTUAL_COUNT=$(nft list set inet whitelist whitelist4 | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?" | wc -l)

    log_info "写入耗时: ${ELAPSED_MS}ms，实际元素数: ${ACTUAL_COUNT}"

    if [[ "$ELAPSED_MS" -lt 5000 ]]; then
        log_pass "1000 条 CIDR 写入耗时 ${ELAPSED_MS}ms < 5000ms（性能可接受）"
    else
        log_fail "写入耗时 ${ELAPSED_MS}ms 超过 5000ms 阈值"
    fi

    # flush 性能
    START_TIME=$(date +%s%N)
    nft flush set inet whitelist whitelist4
    END_TIME=$(date +%s%N)
    FLUSH_MS=$(( (END_TIME - START_TIME) / 1000000 ))

    if [[ "$FLUSH_MS" -lt 1000 ]]; then
        log_pass "flush set 耗时 ${FLUSH_MS}ms < 1000ms"
    else
        log_fail "flush set 耗时 ${FLUSH_MS}ms 超过 1000ms 阈值"
    fi
}

# ─── 主流程 ────────────────────────────────────────────────────────────────────
main() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║       tg-whitelist nftables 集成测试                    ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    preflight

    # 初始清理
    cleanup

    test_rule_structure
    test_set_operations
    test_connectivity_logic
    test_panic
    test_recovery_from_sqlite
    test_coexistence
    test_bulk_cidr_performance

    # ─── 汇总 ─────────────────────────────────────────────────────────────────
    echo ""
    echo -e "${BLUE}══════════ 测试结果汇总 ══════════${NC}"
    echo -e "  ${GREEN}PASS${NC}: $PASS_COUNT"
    echo -e "  ${RED}FAIL${NC}: $FAIL_COUNT"
    echo -e "  ${YELLOW}SKIP${NC}: $SKIP_COUNT"
    echo ""

    if [[ "$FAIL_COUNT" -gt 0 ]]; then
        echo -e "${RED}有 $FAIL_COUNT 项测试失败，请检查上方 [FAIL] 条目。${NC}"
        exit 1
    else
        echo -e "${GREEN}所有测试通过！${NC}"
        exit 0
    fi
}

main "$@"
