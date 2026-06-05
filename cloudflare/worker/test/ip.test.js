import { describe, it, expect } from 'vitest';
import { isPublicIPv4 } from '../src/index.js';

describe('isPublicIPv4', () => {
  // ---- 合法公网 IPv4（应该通过）----
  describe('valid public IPv4', () => {
    it('正常公网地址', () => {
      expect(isPublicIPv4('8.8.8.8')).toBe(true);
      expect(isPublicIPv4('1.1.1.1')).toBe(true);
      expect(isPublicIPv4('114.114.114.114')).toBe(true);
      expect(isPublicIPv4('203.0.113.1')).toBe(true);
    });

    it('边界值：每段最大 255', () => {
      expect(isPublicIPv4('1.0.0.1')).toBe(true);
      expect(isPublicIPv4('223.255.255.255')).toBe(true); // 组播边界以下
    });
  });

  // ---- 私有地址（RFC 1918）----
  describe('private RFC 1918', () => {
    it('10.0.0.0/8', () => {
      expect(isPublicIPv4('10.0.0.0')).toBe(false);
      expect(isPublicIPv4('10.0.0.1')).toBe(false);
      expect(isPublicIPv4('10.255.255.255')).toBe(false);
    });

    it('172.16.0.0/12', () => {
      expect(isPublicIPv4('172.16.0.0')).toBe(false);
      expect(isPublicIPv4('172.20.1.1')).toBe(false);
      expect(isPublicIPv4('172.31.255.255')).toBe(false);
    });

    it('172.15.x 和 172.32.x 应通过（不在 /12 范围）', () => {
      expect(isPublicIPv4('172.15.255.255')).toBe(true);
      expect(isPublicIPv4('172.32.0.0')).toBe(true);
    });

    it('192.168.0.0/16', () => {
      expect(isPublicIPv4('192.168.0.0')).toBe(false);
      expect(isPublicIPv4('192.168.1.1')).toBe(false);
      expect(isPublicIPv4('192.168.255.255')).toBe(false);
    });
  });

  // ---- 回环 ----
  describe('loopback 127.0.0.0/8', () => {
    it('127.0.0.1', () => {
      expect(isPublicIPv4('127.0.0.1')).toBe(false);
    });
    it('127.0.0.0 ~ 127.255.255.255', () => {
      expect(isPublicIPv4('127.0.0.0')).toBe(false);
      expect(isPublicIPv4('127.255.255.255')).toBe(false);
    });
  });

  // ---- 链路本地 ----
  describe('link-local 169.254.0.0/16', () => {
    it('169.254.x.x', () => {
      expect(isPublicIPv4('169.254.0.0')).toBe(false);
      expect(isPublicIPv4('169.254.1.1')).toBe(false);
      expect(isPublicIPv4('169.254.255.255')).toBe(false);
    });
  });

  // ---- CGNAT ----
  describe('CGNAT 100.64.0.0/10', () => {
    it('100.64.0.0 ~ 100.127.255.255', () => {
      expect(isPublicIPv4('100.64.0.0')).toBe(false);
      expect(isPublicIPv4('100.100.1.1')).toBe(false);
      expect(isPublicIPv4('100.127.255.255')).toBe(false);
    });

    it('100.63.x 应通过（不在 CGNAT 范围）', () => {
      expect(isPublicIPv4('100.63.255.255')).toBe(true);
    });

    it('100.128.x 应通过（不在 CGNAT 范围）', () => {
      expect(isPublicIPv4('100.128.0.0')).toBe(true);
    });
  });

  // ---- 保留（0/8）----
  describe('reserved 0.0.0.0/8', () => {
    it('0.0.0.0', () => {
      expect(isPublicIPv4('0.0.0.0')).toBe(false);
    });
    it('0.x.x.x', () => {
      expect(isPublicIPv4('0.255.255.255')).toBe(false);
    });
  });

  // ---- 保留（240/4）----
  describe('reserved 240.0.0.0/4', () => {
    it('240.0.0.0 ~ 254.x.x.x', () => {
      expect(isPublicIPv4('240.0.0.0')).toBe(false);
      expect(isPublicIPv4('248.1.2.3')).toBe(false);
      expect(isPublicIPv4('254.255.255.255')).toBe(false);
    });
  });

  // ---- 广播 ----
  describe('broadcast 255.255.255.255', () => {
    it('255.255.255.255', () => {
      expect(isPublicIPv4('255.255.255.255')).toBe(false);
    });
  });

  // ---- 组播 ----
  describe('multicast 224.0.0.0/4', () => {
    it('224.0.0.0 ~ 239.x.x.x', () => {
      expect(isPublicIPv4('224.0.0.0')).toBe(false);
      expect(isPublicIPv4('230.1.2.3')).toBe(false);
      expect(isPublicIPv4('239.255.255.255')).toBe(false);
    });
  });

  // ---- IPv6 地址 ----
  describe('IPv6 rejected', () => {
    it('标准 IPv6', () => {
      expect(isPublicIPv4('2408:8701::1')).toBe(false);
      expect(isPublicIPv4('::1')).toBe(false);
      expect(isPublicIPv4('fe80::1')).toBe(false);
      expect(isPublicIPv4('2001:db8::1')).toBe(false);
    });
  });

  // ---- 格式非法 ----
  describe('malformed input', () => {
    it('非字符串类型', () => {
      expect(isPublicIPv4(null)).toBe(false);
      expect(isPublicIPv4(undefined)).toBe(false);
      expect(isPublicIPv4(12345)).toBe(false);
      expect(isPublicIPv4([])).toBe(false);
      expect(isPublicIPv4({})).toBe(false);
    });

    it('空字符串 / 空白', () => {
      expect(isPublicIPv4('')).toBe(false);
      expect(isPublicIPv4('   ')).toBe(false);
    });

    it('段数不足 / 过多', () => {
      expect(isPublicIPv4('1.2.3')).toBe(false);
      expect(isPublicIPv4('1.2.3.4.5')).toBe(false);
      expect(isPublicIPv4('1.2')).toBe(false);
    });

    it('段值超出 0–255', () => {
      expect(isPublicIPv4('256.0.0.1')).toBe(false);
      expect(isPublicIPv4('1.256.0.0')).toBe(false);
      expect(isPublicIPv4('1.0.0.256')).toBe(false);
      expect(isPublicIPv4('-1.0.0.1')).toBe(false);
    });

    it('含字母 / 特殊字符', () => {
      expect(isPublicIPv4('abc.def.ghi.jkl')).toBe(false);
      expect(isPublicIPv4('1.2.3.4a')).toBe(false);
      expect(isPublicIPv4('1.2.3.4/')).toBe(false);
    });

    it('有前导零', () => {
      // 01.02.03.04 在某些实现中解析为八进制，应拒绝
      expect(isPublicIPv4('01.02.03.04')).toBe(false);
      expect(isPublicIPv4('8.8.08.8')).toBe(false);
    });

    it('含空格', () => {
      expect(isPublicIPv4(' 8.8.8.8')).toBe(false);
      expect(isPublicIPv4('8.8.8.8 ')).toBe(false);
      expect(isPublicIPv4('8.8. 8.8')).toBe(false);
    });

    it('CIDR 记法', () => {
      expect(isPublicIPv4('8.8.8.0/24')).toBe(false);
    });
  });
});
