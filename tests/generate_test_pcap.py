#!/usr/bin/env python3
# ============================================================
# 合成攻击 PCAP 生成器 — 用于测试新增规则
# ============================================================
# 生成覆盖 SSRF/XXE/SSTI/WebShell/NoSQL 注入等新规则的测试 PCAP
# 原理: 构造 Scapy IP/TCP/HTTP 数据包，写入 pcap 文件
# ============================================================

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from scapy.all import IP, TCP, Raw, wrpcap
except ImportError:
    print("需要安装 Scapy: pip install scapy")
    sys.exit(1)


def make_http_packet(src_ip: str, dst_ip: str, sport: int,
                     request_line: str, headers: str = "",
                     body: str = "") -> bytes:
    """构造一个简单的 HTTP 请求包（TCP + IP + HTTP 载荷）"""
    http_data = f"{request_line}\r\n{headers}\r\n\r\n{body}".encode()
    pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=80,
                                            flags='PA', seq=1000) / Raw(load=http_data)
    return pkt


def main():
    output_dir = os.path.join(os.path.dirname(__file__), 'test_pcaps')
    os.makedirs(output_dir, exist_ok=True)

    packets = []

    # ─── SSRF 攻击 (WEB-007) ───
    packets.append(make_http_packet(
        '10.0.0.1', '192.168.1.1', 40001,
        'GET /fetch?url=http://127.0.0.1:8080/admin HTTP/1.1',
        'Host: vulnerable-app.com'))
    packets.append(make_http_packet(
        '10.0.0.1', '192.168.1.1', 40002,
        'GET /proxy?dest=file:///etc/passwd HTTP/1.1',
        'Host: vulnerable-app.com'))
    packets.append(make_http_packet(
        '10.0.0.1', '192.168.1.1', 40003,
        'GET /redirect?path=gopher://127.0.0.1:6379/_INFO HTTP/1.1',
        'Host: vulnerable-app.com'))

    # ─── XXE 攻击 (WEB-008) ───
    xxe_body = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>"""
    packets.append(make_http_packet(
        '10.0.0.2', '192.168.1.1', 40004,
        'POST /api/xml HTTP/1.1',
        'Host: vulnerable-app.com\r\nContent-Type: application/xml',
        xxe_body))

    # ─── SSTI 攻击 (WEB-009) ───
    packets.append(make_http_packet(
        '10.0.0.3', '192.168.1.1', 40005,
        'GET /profile?name={{7*7}} HTTP/1.1',
        'Host: vulnerable-app.com'))
    packets.append(make_http_packet(
        '10.0.0.3', '192.168.1.1', 40006,
        'GET /debug?data={{config.__class__.__init__.__globals__}} HTTP/1.1',
        'Host: vulnerable-app.com'))

    # ─── WebShell 攻击 (WSHELL-001/004) ───
    ant_body = "pass=@ini_set('display_errors','0');@set_time_limit(0);echo 'OK';"
    packets.append(make_http_packet(
        '10.0.0.4', '192.168.1.1', 40007,
        'POST /shell.php HTTP/1.1',
        'Host: target.com\r\nContent-Type: application/x-www-form-urlencoded',
        ant_body))
    packets.append(make_http_packet(
        '10.0.0.4', '192.168.1.1', 40008,
        'POST /upload.php HTTP/1.1',
        'Host: target.com\r\nContent-Type: application/x-www-form-urlencoded',
        'cmd=eval($_POST[z0]);'))

    # ─── NoSQL 注入 (SQLI-016) ───
    packets.append(make_http_packet(
        '10.0.0.5', '192.168.1.1', 40009,
        'GET /api/users?filter={"$gt":""} HTTP/1.1',
        'Host: api.example.com'))
    packets.append(make_http_packet(
        '10.0.0.5', '192.168.1.1', 40010,
        'GET /api/login?user=admin&pass={"$ne":""} HTTP/1.1',
        'Host: api.example.com'))

    # ─── 正常流量（不触发告警）───
    packets.append(make_http_packet(
        '192.168.1.50', '192.168.1.1', 40011,
        'GET /index.html HTTP/1.1',
        'Host: example.com'))
    packets.append(make_http_packet(
        '192.168.1.50', '192.168.1.1', 40012,
        'GET /api/status HTTP/1.1',
        'Host: example.com\r\nAccept: application/json'))

    # ─── 写入 PCAP ───
    output_path = os.path.join(output_dir, 'extended_attacks.pcap')
    wrpcap(output_path, packets)
    print(f"生成完成: {output_path} ({len(packets)} 包)")
    print("覆盖类别: SSRF / XXE / SSTI / WebShell / NoSQL Injection / Normal")


if __name__ == '__main__':
    main()
