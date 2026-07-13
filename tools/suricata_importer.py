#!/usr/bin/env python3
# ============================================================
# Suricata 规则导入器 — 将 Suricata/Snort 规则转为 NADS YAML 格式
# ============================================================
# 用法:
#   python tools/suricata_importer.py <suricata.rules> --out signatures/
#   python tools/suricata_importer.py community.rules --category web_attack
#
# Suricata 规则格式参考:
#   alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS \
#       (msg:"SQL Injection Attempt"; flow:to_server,established; \
#        content:"UNION SELECT"; nocase; http_uri; \
#        classtype:web-application-attack; sid:1000001; rev:1;)
# ============================================================

import re
import os
import sys
import yaml
import argparse
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

# ─── Suricata classtype → NADS severity 映射 ───
CLASSTYPE_SEVERITY = {
    'attempted-admin':    'high',
    'attempted-user':     'high',
    'inappropriate-content': 'medium',
    'policy-violation':   'medium',
    'shellcode-detect':   'critical',
    'successful-admin':   'critical',
    'successful-user':    'critical',
    'trojan-activity':    'critical',
    'unsuccessful-user':  'medium',
    'unsuccessful-admin': 'medium',
    'web-application-attack': 'high',
    'web-application-activity': 'medium',
    'attempted-dos':      'high',
    'attempted-recon':    'medium',
    'bad-unknown':        'high',
    'default-login-attempt': 'medium',
    'denial-of-service':  'critical',
    'misc-attack':        'medium',
    'non-standard-protocol': 'low',
    'not-suspicious':     'low',
    'social-engineering': 'medium',
    'suspicious-login':   'high',
    'system-call-detect': 'high',
    'unknown':            'medium',
}

# ─── Suricata classtype → NADS category 映射 ───
CLASSTYPE_CATEGORY = {
    'web-application-attack':  'web_attack',
    'web-application-activity': 'web_attack',
    'attempted-recon':         'scan',
    'trojan-activity':         'backdoor',
    'shellcode-detect':        'backdoor',
    'attempted-dos':           'dos',
    'denial-of-service':       'dos',
    'attempted-admin':         'brute_force',
    'attempted-user':          'brute_force',
    'default-login-attempt':   'brute_force',
    'suspicious-login':        'brute_force',
    'misc-attack':             'web_attack',
    'social-engineering':      'xss',
}


class SuricataRule:
    """单条 Suricata 规则的解析结果"""

    __slots__ = ('action', 'protocol', 'src_ip', 'src_port',
                 'dst_ip', 'dst_port', 'msg', 'contents',
                 'classtype', 'sid', 'rev', 'raw')

    def __init__(self, raw: str):
        self.raw = raw
        self.action = ''
        self.protocol = ''
        self.src_ip = ''
        self.src_port = ''
        self.dst_ip = ''
        self.dst_port = ''
        self.msg = ''
        self.contents: List[str] = []
        self.classtype = ''
        self.sid = ''
        self.rev = ''


class SuricataImporter:
    """
    Suricata/Snort 规则导入器

    将行业标准的 Suricata 规则文件转换为 NADS 的 YAML 格式。
    支持 community.rules、emerging-threats 等规则源。
    """

    # 规则行正则: action proto src_ip src_port -> dst_ip dst_port (options)
    RULE_RE = re.compile(
        r'^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*->\s*(\S+)\s+(\S+)\s*\((.*)\)\s*$'
    )

    # content 提取: content:"...";  (支持 ! 否定)
    CONTENT_RE = re.compile(r'content:\s*"((?:[^"\\]|\\.)*)"\s*;')

    # 关键字提取
    MSG_RE = re.compile(r'msg:\s*"((?:[^"\\]|\\.)*)"\s*;')
    CLASSTYPE_RE = re.compile(r'classtype:\s*(\S+)\s*;')
    SID_RE = re.compile(r'sid:\s*(\d+)\s*;')
    REV_RE = re.compile(r'rev:\s*(\d+)\s*;')

    def __init__(self):
        self.rules: List[SuricataRule] = []
        self.stats = {'total': 0, 'parsed': 0, 'skipped': 0}

    def parse_file(self, filepath: str) -> int:
        """解析 Suricata 规则文件"""
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        for line in lines:
            line = line.strip()
            # 跳过注释和空行
            if not line or line.startswith('#'):
                continue

            rule = self._parse_rule(line)
            if rule and rule.contents:
                self.rules.append(rule)
                self.stats['parsed'] += 1
            else:
                self.stats['skipped'] += 1
            self.stats['total'] += 1

        logger.info(
            f"解析完成: {self.stats['total']} 行 → "
            f"{self.stats['parsed']} 条规则, "
            f"跳过 {self.stats['skipped']} 条（无 content 或解析失败）"
        )
        return self.stats['parsed']

    def _parse_rule(self, line: str) -> Optional[SuricataRule]:
        """解析单行 Suricata 规则"""
        match = self.RULE_RE.match(line)
        if not match:
            return None

        rule = SuricataRule(line)
        rule.action, rule.protocol = match.group(1), match.group(2)
        rule.src_ip, rule.src_port = match.group(3), match.group(4)
        rule.dst_ip, rule.dst_port = match.group(5), match.group(6)
        options = match.group(7)

        # 提取 msg
        msg_match = self.MSG_RE.search(options)
        rule.msg = msg_match.group(1) if msg_match else 'Imported Rule'

        # 提取 classtype
        ct_match = self.CLASSTYPE_RE.search(options)
        rule.classtype = ct_match.group(1) if ct_match else 'unknown'

        # 提取 sid/rev
        sid_match = self.SID_RE.search(options)
        rule.sid = sid_match.group(1) if sid_match else ''
        rev_match = self.REV_RE.search(options)
        rule.rev = rev_match.group(1) if rev_match else '1'

        # 提取所有 content
        rule.contents = self.CONTENT_RE.findall(options)
        # 也支持 content:|hex| 格式
        hex_contents = re.findall(r'content:\s*\|([0-9a-fA-F\s]+)\|\s*;', options)
        for h in hex_contents:
            try:
                rule.contents.append(bytes.fromhex(h).decode('latin-1'))
            except Exception:
                pass

        return rule if rule.contents else None

    def to_nads_yaml(self, category: str = None) -> List[Dict[str, Any]]:
        """将所有解析的规则转为 NADS YAML 格式"""
        signatures = []
        seen_sids = set()

        for rule in self.rules:
            if rule.sid in seen_sids:
                continue
            seen_sids.add(rule.sid)

            # 确定 category
            cat = category or CLASSTYPE_CATEGORY.get(
                rule.classtype, 'web_attack')

            # 确定 severity
            severity = CLASSTYPE_SEVERITY.get(rule.classtype, 'medium')

            # 确定端口
            ports = self._extract_ports(rule.dst_port)

            # 确定协议
            proto = self._extract_protocol(rule.protocol)

            sig_id = f"SUR-{rule.sid}" if rule.sid else f"SUR-{len(signatures):04d}"

            sig = {
                'id': sig_id,
                'name': f"Suricata: {rule.msg}",
                'category': cat,
                'severity': severity,
                'patterns': rule.contents,
                'enabled': True,
            }
            # 仅当有有效值时才添加可选字段
            if proto is not None:
                sig['protocols'] = [proto]
            if ports is not None:
                sig['ports'] = ports
            signatures.append(sig)

        return signatures

    def _extract_ports(self, port_str: str) -> Optional[List[int]]:
        """提取端口列表"""
        ports = []
        if port_str in ('any', '$HTTP_PORTS'):
            return [80, 443, 8080, 8443]
        if port_str == '$SSH_PORTS':
            return [22]
        # 尝试解析 80,443 或 80:443 格式
        for part in port_str.strip('[]').split(','):
            part = part.strip()
            if ':' in part:
                try:
                    lo, hi = part.split(':')
                    ports.extend(range(int(lo), int(hi) + 1))
                except ValueError:
                    pass
            elif part.isdigit():
                ports.append(int(part))
        return ports if ports else None

    def _extract_protocol(self, proto: str) -> str:
        """映射 Suricata 协议到 NADS 协议"""
        proto_upper = proto.upper()
        mapping = {
            'HTTP': 'HTTP', 'TCP': None, 'UDP': None,
            'ICMP': None, 'DNS': 'DNS', 'FTP': 'FTP',
            'SSH': 'SSH', 'SMTP': 'SMTP', 'TLS': 'TLS',
        }
        return mapping.get(proto_upper, None)

    def export_yaml(self, output_dir: str, category: str = None,
                    filename: str = 'imported_suricata.yaml') -> str:
        """导出为 NADS YAML 文件"""
        signatures = self.to_nads_yaml(category)
        if not signatures:
            logger.warning("没有可导出的规则")
            return ''

        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, filename)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('# ==============================================\n')
            f.write('# Suricata 规则导入 — 自动生成\n')
            f.write(f'# 导入规则数: {len(signatures)}\n')
            f.write('# ==============================================\n\n')
            yaml.dump(signatures, f, default_flow_style=False,
                      allow_unicode=True, sort_keys=False)

        logger.info(f"导出完成: {output_path} ({len(signatures)} 条规则)")
        return output_path


# ============================================================
# 内置演示：无需外部文件即可生成示例规则
# ============================================================

SAMPLE_SURICATA_RULES = """
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"SQL Injection - UNION SELECT"; flow:to_server,established; content:"UNION SELECT"; nocase; http_uri; classtype:web-application-attack; sid:1000001; rev:1;)
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"SQL Injection - OR 1=1"; flow:to_server,established; content:"OR 1=1"; nocase; http_uri; classtype:web-application-attack; sid:1000002; rev:1;)
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"XSS - Script Tag"; flow:to_server,established; content:"<script"; nocase; http_uri; classtype:web-application-attack; sid:1000003; rev:1;)
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Directory Traversal"; flow:to_server,established; content:"../"; nocase; http_uri; classtype:web-application-attack; sid:1000004; rev:1;)
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"PHP Code Injection"; flow:to_server,established; content:"<?php"; nocase; http_uri; classtype:web-application-attack; sid:1000005; rev:1;)
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Command Injection - wget"; flow:to_server,established; content:"wget "; nocase; http_uri; classtype:web-application-attack; sid:1000006; rev:1;)
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WebShell - eval POST"; flow:to_server,established; content:"eval"; nocase; http_client_body; classtype:web-application-attack; sid:1000007; rev:1;)
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"SQL Injection - information_schema"; flow:to_server,established; content:"information_schema"; nocase; http_uri; classtype:web-application-attack; sid:1000008; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; flow:to_server,established; content:"Failed password"; nocase; classtype:attempted-admin; sid:2000001; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"FTP Brute Force Attempt"; flow:to_server,established; content:"530 Login"; nocase; classtype:attempted-admin; sid:2000002; rev:1;)
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Nikto Scan Detected"; flow:to_server,established; content:"Nikto"; nocase; http_header; classtype:attempted-recon; sid:3000001; rev:1;)
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"SQLMap Attack"; flow:to_server,established; content:"sqlmap"; nocase; http_header; classtype:web-application-attack; sid:3000002; rev:1;)
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Slowloris Attack"; flow:to_server,established; content:"X-a: b"; nocase; http_header; classtype:attempted-dos; sid:4000001; rev:1;)
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"File Inclusion - /etc/passwd"; flow:to_server,established; content:"/etc/passwd"; nocase; http_uri; classtype:web-application-attack; sid:1000009; rev:1;)
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ShellShock Attack"; flow:to_server,established; content:"() {"; http_header; classtype:web-application-attack; sid:1000010; rev:1;)
""".strip()


def main():
    parser = argparse.ArgumentParser(
        description='Suricata 规则导入器 — 将 Suricata 规则转为 NADS YAML')
    parser.add_argument('rules_file', nargs='?',
                        help='Suricata 规则文件路径（不指定则使用内置示例）')
    parser.add_argument('--out', '-o', default='./signatures',
                        help='输出目录 (默认: ./signatures)')
    parser.add_argument('--category', '-c', default=None,
                        help='统一指定类别 (默认: 根据 classtype 自动映射)')
    parser.add_argument('--sample', '-s', action='store_true',
                        help='使用内置示例规则演示')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s')

    importer = SuricataImporter()

    if args.rules_file and not args.sample:
        count = importer.parse_file(args.rules_file)
    else:
        # 使用内置示例
        logger.info("使用内置 15 条示例 Suricata 规则")
        import tempfile
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.rules', delete=False
        ) as f:
            f.write(SAMPLE_SURICATA_RULES)
            tmp_path = f.name
        count = importer.parse_file(tmp_path)
        os.unlink(tmp_path)

    if count == 0:
        logger.error("未解析到任何规则，退出")
        return

    output_path = importer.export_yaml(args.out, args.category)
    logger.info(f"成功导入 {count} 条 Suricata 规则 → {output_path}")


if __name__ == '__main__':
    main()
