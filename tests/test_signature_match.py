#!/usr/bin/env python3
# ============================================================
# 测试: 特征匹配准确性测试
# 使用构造的攻击载荷验证特征库匹配效果
# ============================================================

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.misuse_detector import SignatureMatcher
from core.protocol_parser import ProtocolParser


class SignatureTestSuite:
    """特征匹配测试套件"""

    def __init__(self):
        self.matcher = SignatureMatcher('../signatures')
        self.matcher.load_all()

    def test_sql_injection(self) -> dict:
        """测试 SQL 注入检测"""
        tests = [
            # (描述, 载荷, 期望检测到)
            ("UNION SELECT 注入",
             b"GET /page.php?id=1 UNION SELECT * FROM users HTTP/1.1",
             True),
            ("1=1 永真式注入",
             b"GET /login.php?user=admin' OR '1'='1'-- HTTP/1.1",
             True),
            ("DROP TABLE 注入",
             b"GET /page.php?id=1; DROP TABLE users;-- HTTP/1.1",
             True),
            ("正常请求 - 不应触发",
             b"GET /index.html HTTP/1.1\r\nHost: example.com",
             False),
            ("Information Schema 探测",
             b"GET /?id=1 UNION SELECT table_name FROM information_schema.tables HTTP/1.1",
             True),
            ("Sleep 盲注",
             b"GET /?id=1 AND SLEEP(5) HTTP/1.1",
             True),
            ("SQLMap UA",
             b"GET / HTTP/1.1\r\nUser-Agent: sqlmap/1.6#stable",
             True),
        ]

        return self._run_tests("SQL 注入", tests)

    def test_xss(self) -> dict:
        """测试 XSS 检测"""
        tests = [
            ("Script 标签注入",
             b"GET /search?q=<script>alert(1)</script> HTTP/1.1",
             True),
            ("IMG Onerror 注入",
             b"GET /?x=<img src=x onerror=alert(1)> HTTP/1.1",
             True),
            ("JavaScript 协议",
             b"GET /?url=javascript:alert(document.cookie) HTTP/1.1",
             True),
            ("正常 HTML - 不应触发",
             b"GET /page.html HTTP/1.1\r\nHost: example.com",
             False),
            ("URL 编码 XSS",
             b"GET /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1",
             True),
        ]

        return self._run_tests("XSS", tests)

    def test_web_attack(self) -> dict:
        """测试 Web 攻击检测"""
        tests = [
            ("目录遍历",
             b"GET /../../etc/passwd HTTP/1.1",
             True),
            ("命令注入",
             b"GET /ping?ip=127.0.0.1|cat /etc/passwd HTTP/1.1",
             True),
            ("PHP 代码执行",
             b"GET /?cmd=<?php system($_GET['c']);?> HTTP/1.1",
             True),
            ("Web Shell 探测",
             b"GET /cmd.php HTTP/1.1",
             True),
            ("正常请求",
             b"GET /about.html HTTP/1.1\r\nHost: example.com",
             False),
        ]

        return self._run_tests("Web 攻击", tests)

    def test_brute_force(self) -> dict:
        """测试暴力破解检测"""
        tests = [
            ("SSH 失败",
             b"Failed password for root from 10.0.0.1 port 22 ssh2",
             True),
            ("FTP 失败",
             b"530 Login incorrect.",
             True),
        ]

        return self._run_tests("暴力破解", tests)

    def _run_tests(self, category: str, tests: list) -> dict:
        """运行一组测试"""
        passed = 0
        failed = 0
        details = []

        for desc, payload, expected in tests:
            parsed = {
                'src_ip': '192.168.1.100',
                'dst_ip': '192.168.1.1',
                'src_port': 12345,
                'dst_port': 80,
                'payload': payload,
                'timestamp': 0,
                'app_protocol': 'HTTP',
            }

            alerts = self.matcher.match_packet(parsed)
            detected = len(alerts) > 0
            status = "✓" if detected == expected else "✗"

            if detected == expected:
                passed += 1
            else:
                failed += 1

            details.append({
                'desc': desc,
                'expected': expected,
                'detected': detected,
                'status': status,
                'alerts': [a['signature_name'] for a in alerts],
            })

        return {
            'category': category,
            'total': len(tests),
            'passed': passed,
            'failed': failed,
            'accuracy': passed / max(len(tests), 1),
            'details': details,
        }

    def run_all(self):
        """运行所有测试"""
        print("=" * 60)
        print("  IDS 特征库匹配准确性测试")
        print("=" * 60)

        all_results = []
        all_results.append(self.test_sql_injection())
        all_results.append(self.test_xss())
        all_results.append(self.test_web_attack())
        all_results.append(self.test_brute_force())

        # 汇总
        print("\n" + "=" * 60)
        print("  测试汇总")
        print("=" * 60)

        total_passed = sum(r['passed'] for r in all_results)
        total_tests = sum(r['total'] for r in all_results)

        for r in all_results:
            print(f"\n[{r['category']}] 准确率: {r['accuracy']:.0%} "
                  f"({r['passed']}/{r['total']})")
            for d in r['details']:
                print(f"  {d['status']} {d['desc']}")
                if d['alerts']:
                    print(f"      触发: {', '.join(d['alerts'])}")

        print(f"\n{'='*60}")
        print(f"总准确率: {total_passed/total_tests:.0%} "
              f"({total_passed}/{total_tests})")
        print(f"{'='*60}")

        return total_passed == total_tests


if __name__ == '__main__':
    suite = SignatureTestSuite()
    success = suite.run_all()
    sys.exit(0 if success else 1)
