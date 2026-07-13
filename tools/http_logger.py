#!/usr/bin/env python3
# ============================================================
# HTTP 结构化日志 — 从PCAP提取HTTP请求元数据 (Zeek风格)
# ============================================================
# 输出每个HTTP请求的 method/uri/host/user_agent/status 等
# 用法:
#   python tools/http_logger.py tests/test_pcaps/extended_attacks.pcap
#   python tools/http_logger.py --json output.json tests/test_pcaps/*.pcap
# ============================================================

import sys
import os
import json
import argparse
from typing import Dict, List, Any
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.packet_capture import PacketCapture
from core.protocol_parser import ProtocolParser, AppProtocol


class HTTPLogger:
    """HTTP请求结构化日志记录器 (Zeek http.log 风格)"""

    def __init__(self):
        self.entries: List[Dict] = []
        self.parser = ProtocolParser()

    def on_packet(self, pkt) -> None:
        parsed = self.parser.parse(pkt)
        if parsed is None:
            return

        proto = parsed.get('app_protocol')
        if proto != AppProtocol.HTTP:
            return

        payload = parsed.get('payload', b'')
        if not payload:
            return

        # 提取HTTP响应状态码（如果有）
        status_code = self._extract_status(payload)

        entry = {
            'ts':       datetime.fromtimestamp(
                parsed.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S'),
            'src_ip':   parsed.get('src_ip', ''),
            'src_port': parsed.get('src_port', 0),
            'dst_ip':   parsed.get('dst_ip', ''),
            'dst_port': parsed.get('dst_port', 0),
            'method':   parsed.get('http_method') or self._guess_method(payload),
            'uri':      parsed.get('http_uri', ''),
            'host':     parsed.get('http_host', ''),
            'user_agent': parsed.get('http_user_agent', ''),
            'status_code': status_code,
            'payload_len': parsed.get('payload_len', 0),
            'referer':  self._extract_header(payload, 'Referer'),
        }
        self.entries.append(entry)

    def _extract_status(self, payload: bytes) -> int:
        """从HTTP响应中提取状态码"""
        try:
            text = payload.decode('utf-8', errors='ignore')[:200]
            if text.startswith('HTTP/'):
                parts = text.split(' ')
                if len(parts) >= 2 and parts[1].isdigit():
                    return int(parts[1])
        except Exception:
            pass
        return 0

    def _guess_method(self, payload: bytes) -> str:
        """如果parser没给出method，从第一行推断"""
        try:
            first_line = payload.decode('utf-8', errors='ignore').split('\r\n')[0]
            return first_line.split(' ')[0] if ' ' in first_line else 'UNKNOWN'
        except Exception:
            return 'UNKNOWN'

    def _extract_header(self, payload: bytes, name: str) -> str:
        """从HTTP载荷中提取指定头部"""
        try:
            text = payload.decode('utf-8', errors='ignore')
            for line in text.split('\r\n'):
                if ':' in line and line.split(':')[0].strip().lower() == name.lower():
                    return line.split(':', 1)[1].strip()
        except Exception:
            pass
        return ''

    def get_summary(self) -> Dict:
        """生成统计摘要"""
        methods = {}
        hosts = {}
        statuses = {}
        for e in self.entries:
            m = e['method']
            methods[m] = methods.get(m, 0) + 1
            h = e['host']
            if h:
                hosts[h] = hosts.get(h, 0) + 1
            s = e['status_code']
            if s:
                statuses[s] = statuses.get(s, 0) + 1

        return {
            'total_http_requests': len(self.entries),
            'unique_src_ips': len(set(e['src_ip'] for e in self.entries)),
            'methods': methods,
            'top_hosts': sorted(hosts.items(), key=lambda x: -x[1])[:5],
            'statuses': statuses,
        }


def main():
    parser = argparse.ArgumentParser(description='HTTP结构化日志 (Zeek风格)')
    parser.add_argument('pcap', nargs='+', help='PCAP文件路径')
    parser.add_argument('--json', '-j', type=str, help='输出JSON文件')
    parser.add_argument('--summary', '-s', action='store_true',
                        help='只输出摘要')
    args = parser.parse_args()

    logger = HTTPLogger()

    for pcap_path in args.pcap:
        if not os.path.exists(pcap_path):
            print(f"跳过: {pcap_path}")
            continue

        capture = PacketCapture()
        capture.add_callback(logger.on_packet)
        capture.replay_pcap(pcap_path)

    if args.summary:
        summary = logger.get_summary()
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    else:
        print(f"\nHTTP请求总数: {len(logger.entries)}")
        print(f"{'时间':<20} {'方法':<8} {'URI':<40} {'源IP':<18} {'状态':>5}")
        print('-' * 95)
        for e in logger.entries[:50]:
            uri = e['uri'][:38] if e['uri'] else '-'
            print(
                f"{e['ts']:<20} {e['method']:<8} {uri:<40} "
                f"{e['src_ip']:<18} {e['status_code']:>5}"
            )
        if len(logger.entries) > 50:
            print(f"... 还有 {len(logger.entries) - 50} 条")

    if args.json:
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump({
                'entries': logger.entries,
                'summary': logger.get_summary(),
            }, f, indent=2, ensure_ascii=False)
        print(f"\nJSON导出: {args.json}")


if __name__ == '__main__':
    main()
