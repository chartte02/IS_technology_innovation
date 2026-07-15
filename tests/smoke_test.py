#!/usr/bin/env python3
"""NADS 端到端冒烟测试 — 一键验证整套系统"""
import sys, os, time, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

TESTS = [
    ("签名匹配", "python tests/test_signature_match.py", "100%"),
    ("Flowbits",  "python tests/test_flowbits.py", "通过"),
    ("Ping",      "python -c \"import scapy, yaml, PyQt5, ahocorasick; print('OK')\"", "OK"),
]

PCAPS = [
    ("基础攻击", "tests/test_pcaps/synthetic_attacks.pcap"),
    ("扩展攻击", "tests/test_pcaps/extended_attacks.pcap"),
]

TOOLS = [
    ("威胁情报",   "python tools/threat_intel.py --ip 10.0.0.55"),
    ("规则检查",   "python tools/rule_quality_check.py"),
    ("HTTP日志",   "python tools/http_logger.py --summary tests/test_pcaps/extended_attacks.pcap"),
    ("性能剖析",   "python tools/perf_profiler.py --rounds 50 --top 3"),
    ("Fuzzing",    "python tools/fuzz_test.py --count 1000"),
]


def run(cmd, timeout=30):
    """运行命令并返回 (success, output)"""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout, cwd=os.path.dirname(__file__) + '/..')
        return r.returncode == 0, r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
    except Exception as e:
        return False, str(e)


def main():
    passed = 0
    failed = 0

    print("=" * 60)
    print("  NADS 端到端冒烟测试")
    print("=" * 60)

    # 1. 基础测试
    print("\n[1/3] 基础功能测试")
    for name, cmd, expect in TESTS:
        ok, out = run(cmd)
        status = "PASS" if expect in out else "FAIL"
        if status == "PASS": passed += 1
        else: failed += 1
        print(f"  [{status}] {name}")

    # 2. 导入测试
    print("\n[2/3] 模块导入")
    imports = [
        ("from core.misuse_detector import SignatureMatcher", "误用检测"),
        ("from core.anomaly_detector import AnomalyDetector", "异常检测"),
        ("from core.alert_manager import AlertManager", "告警管理"),
        ("from core.tls_detector import TLSDetector", "TLS检测"),
    ]
    for imp, name in imports:
        ok, _ = run(f"python -c \"import sys;sys.path.insert(0,'.');{imp};print('OK')\"")
        status = "PASS" if ok else "FAIL"
        if status == "PASS": passed += 1
        else: failed += 1
        print(f"  [{status}] {name}")

    # 3. PCAP 回放
    print("\n[3/3] PCAP 回放检测")
    for name, pcap in PCAPS:
        cmd = f"python main.py --replay {pcap}"
        ok, out = run(cmd, timeout=60)  # PCAP 回放 30s+overhead
        # 检查是否有告警输出
        has_alerts = "CRIT" in out or "HIGH" in out or "告警" in out or "alert" in out.lower()
        status = "PASS" if has_alerts else "FAIL"
        if status == "PASS": passed += 1
        else: failed += 1
        # 提取告警数
        alert_count = "?"
        for line in out.split('\n'):
            if '总计' in line:
                alert_count = line.split('总计')[-1].split('条')[0].strip()
                break
        print(f"  [{status}] {name} ({alert_count} alerts)")

    print(f"\n{'='*60}")
    print(f"  Result: {passed} passed, {failed} failed of {passed+failed}")
    if failed == 0:
        print(f"  [OK] All tests passed!")
    print(f"{'='*60}")
    return failed == 0


if __name__ == '__main__':
    sys.exit(0 if main() else 1)
