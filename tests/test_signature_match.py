#!/usr/bin/env python3
# test_signature_match.py - Accuracy test for misuse detection engine
# Run: python tests/test_signature_match.py
# Run verbose: python tests/test_signature_match.py -v

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.misuse_detector import SignatureMatcher
from core.protocol_parser import AppProtocol


class SignatureTestSuite:
    """Accuracy test suite for signature-based detection"""

    def __init__(self):
        sig_dir = os.path.join(os.path.dirname(__file__), '..', 'signatures')
        self.matcher = SignatureMatcher(sig_dir)
        self.matcher.load_all()

    def _make_parsed(self, payload: bytes, port: int = 80,
                     protocol: str = 'HTTP') -> dict:
        proto_map = {
            'HTTP': AppProtocol.HTTP, 'SSH': AppProtocol.SSH,
            'FTP': AppProtocol.FTP, 'DNS': AppProtocol.DNS,
        }
        return {
            'src_ip': '192.168.1.100', 'dst_ip': '192.168.1.1',
            'src_port': 12345, 'dst_port': port,
            'seq': 100, 'ack': 200, 'flags': 0x18, 'flags_str': 'PA',
            'payload': payload, 'payload_len': len(payload),
            'app_protocol': proto_map.get(protocol, AppProtocol.HTTP),
            'http_method': 'GET', 'http_uri': '/', 'http_host': '',
            'http_user_agent': '', 'timestamp': 0,
        }

    def test_sql_injection(self) -> dict:
        tests = [
            ("UNION SELECT injection", b"GET /page.php?id=1 UNION SELECT * FROM users HTTP/1.1", True),
            ("Tautology ' OR '1'='1'", b"GET /login.php?user=admin' OR '1'='1'-- HTTP/1.1", True),
            ("DROP TABLE injection", b"GET /page.php?id=1; DROP TABLE users;-- HTTP/1.1", True),
            ("Sleep blind injection", b"GET /?id=1 AND SLEEP(5) HTTP/1.1", True),
            ("Normal HTML request", b"GET /index.html HTTP/1.1\r\nHost: example.com", False),
            ("SQLMap User-Agent", b"GET / HTTP/1.1\r\nUser-Agent: sqlmap/1.6#stable", True),
        ]
        return self._run_tests("SQL Injection", tests)

    def test_xss(self) -> dict:
        tests = [
            ("Script tag injection", b"GET /search?q=<script>alert(1)</script> HTTP/1.1", True),
            ("IMG onerror injection", b"GET /?x=<img src=x onerror=alert(1)> HTTP/1.1", True),
            ("Normal HTML page", b"GET /page.html HTTP/1.1\r\nHost: example.com", False),
            ("URL-encoded XSS", b"GET /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1", True),
        ]
        return self._run_tests("XSS", tests)

    def test_web_attack(self) -> dict:
        tests = [
            ("Path traversal", b"GET /../../etc/passwd HTTP/1.1", True),
            ("Command injection", b"GET /ping?ip=127.0.0.1|cat /etc/passwd HTTP/1.1", True),
            ("Web shell probe", b"GET /c99shell.php HTTP/1.1", True),
            ("Normal request", b"GET /about.html HTTP/1.1\r\nHost: example.com", False),
        ]
        return self._run_tests("Web Attack", tests)

    def test_brute_force(self) -> dict:
        tests = [
            ("SSH failed password", b"Failed password for root from 10.0.0.1 port 22 ssh2", True),
            ("FTP 530 login incorrect", b"530 Login incorrect.", True),
            ("SSH success - no alert", b"Accepted password for root from 10.0.0.1 port 22 ssh2", False),
        ]
        return self._run_tests("Brute Force", tests)

    def _run_tests(self, category: str, tests: list) -> dict:
        passed = 0; failed = 0; details = []

        for desc, payload, expected in tests:
            parsed = self._make_parsed(payload)
            alerts = self.matcher.match_packet(parsed)
            detected = len(alerts) > 0
            status = "PASS" if detected == expected else "FAIL"

            if detected == expected:
                passed += 1
            else:
                failed += 1

            details.append({
                'desc': desc, 'expected': expected,
                'detected': detected, 'status': status,
                'alerts': [a['signature_name'] for a in alerts],
            })

        return {
            'category': category, 'total': len(tests),
            'passed': passed, 'failed': failed,
            'accuracy': passed / max(len(tests), 1),
            'details': details,
        }

    def run_all(self, verbose: bool = False) -> bool:
        print("=" * 60)
        print("  Signature Detection Accuracy Test")
        print(f"  Loaded {self.matcher.total_loaded} rules")
        print("=" * 60)

        all_results = [
            self.test_sql_injection(),
            self.test_xss(),
            self.test_web_attack(),
            self.test_brute_force(),
        ]

        print("\n" + "=" * 60)
        print("  Results Summary")
        print("=" * 60)

        total_passed = sum(r['passed'] for r in all_results)
        total_tests = sum(r['total'] for r in all_results)

        for r in all_results:
            print(f"\n[{r['category']}] Accuracy: {r['accuracy']:.0%} "
                  f"({r['passed']}/{r['total']})")
            for d in r['details']:
                marker = "[PASS]" if d['status'] == 'PASS' else "[FAIL]"
                print(f"  {marker} {d['desc']}")
                if verbose and d['alerts']:
                    print(f"       Triggered: {', '.join(d['alerts'])}")
                if d['status'] == 'FAIL':
                    print(f"       Expected={d['expected']} Detected={d['detected']}")

        print(f"\n{'='*60}")
        print(f"Overall Accuracy: {total_passed}/{total_tests} = {total_passed/total_tests:.0%}")
        print(f"{'='*60}")

        return total_passed == total_tests


if __name__ == '__main__':
    suite = SignatureTestSuite()
    success = suite.run_all(verbose='-v' in sys.argv)
    sys.exit(0 if success else 1)
