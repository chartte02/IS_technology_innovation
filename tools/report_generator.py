#!/usr/bin/env python3
# ============================================================
# 告警 HTML 报告生成器
# ============================================================
# 用法:
#   python tools/report_generator.py --replay tests/test_pcaps/extended_attacks.pcap
#   python tools/report_generator.py --alerts alerts.json
# ============================================================

import sys
import os
import json
import argparse
import time
from typing import Dict, List

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

SEVERITY_COLORS = {
    'critical': '#d32f2f',
    'high':     '#f57c00',
    'medium':   '#fbc02d',
    'low':      '#1976d2',
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>NADS 检测报告</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; margin: 20px; background: #1e1e2e; color: #cdd6f4; }}
  h1 {{ color: #89b4fa; border-bottom: 2px solid #45475a; padding-bottom: 10px; }}
  .summary {{ display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }}
  .card {{ background: #313244; border-radius: 8px; padding: 15px 25px; min-width: 120px; text-align: center; }}
  .card .num {{ font-size: 2em; font-weight: bold; }}
  .card .label {{ color: #a6adc8; font-size: 0.85em; margin-top: 5px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 20px 0; background: #313244; border-radius: 8px; overflow: hidden; }}
  th {{ background: #45475a; padding: 10px; text-align: left; font-weight: 600; }}
  td {{ padding: 8px 10px; border-top: 1px solid #45475a; }}
  tr:hover {{ background: #45475a; }}
  .sev {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: 600; color: #fff; }}
  .chart-bar {{ display: inline-block; height: 16px; border-radius: 3px; margin-right: 5px; }}
  .mitre {{ font-size: 0.8em; color: #a6adc8; }}
  .footer {{ margin-top: 30px; color: #6c7086; font-size: 0.85em; text-align: center; }}
</style>
</head>
<body>
<h1>🛡️ NADS — 网络攻击检测报告</h1>
<p>生成时间: {timestamp}</p>

<div class="summary">
  {summary_cards}
</div>

<h2>📊 严重度分布</h2>
<div class="summary">
  {severity_bars}
</div>

<h2>📋 告警详情</h2>
<table>
<tr><th>时间</th><th>严重度</th><th>类别</th><th>规则名称</th><th>来源 IP</th><th>目标 IP</th><th>MITRE ATT&amp;CK</th></tr>
{alert_rows}
</table>

<div class="footer">
  NADS — Network Attack Detection System | 91 条规则 · 301 个模式 · 9 大类别
</div>
</body>
</html>
"""


def generate_report(alerts: List[Dict], output_path: str):
    """生成 HTML 报告"""
    if not alerts:
        print("无告警数据")
        return

    # 统计
    cats = {}
    sevs = {}
    for a in alerts:
        cats[a.get('category', '?')] = cats.get(a.get('category', '?'), 0) + 1
        sevs[a.get('severity', '?')] = sevs.get(a.get('severity', '?'), 0) + 1

    # 摘要卡片
    cards = f"""
    <div class="card"><div class="num" style="color:#f38ba8">{len(alerts)}</div><div class="label">告警总数</div></div>
    <div class="card"><div class="num" style="color:#89b4fa">{len(cats)}</div><div class="label">攻击类别</div></div>
    <div class="card"><div class="num" style="color:#a6e3a1">{len(set(a.get('src_ip','') for a in alerts))}</div><div class="label">攻击来源</div></div>
    """

    # 严重度柱状图
    bars = ''
    total = sum(sevs.values())
    for sev in ['critical', 'high', 'medium', 'low']:
        count = sevs.get(sev, 0)
        pct = count / max(total, 1) * 100
        color = SEVERITY_COLORS.get(sev, '#666')
        bars += f"""
    <div class="card">
      <div class="num" style="color:{color}">{count}</div>
      <div class="label">{sev}</div>
      <div class="chart-bar" style="width:{pct*1.5}px;background:{color}"></div>
    </div>"""

    # 告警行
    rows = ''
    for a in sorted(alerts, key=lambda x: x.get('timestamp', 0), reverse=True)[:100]:
        sev = a.get('severity', '?')
        color = SEVERITY_COLORS.get(sev, '#666')
        ts = time.strftime('%H:%M:%S', time.localtime(a.get('timestamp', 0)))
        mitre = a.get('mitre_technique', '')
        rows += f"""<tr>
<td>{ts}</td>
<td><span class="sev" style="background:{color}">{sev}</span></td>
<td>{a.get('category', '?')}</td>
<td>{a.get('signature_name', '?')[:50]}</td>
<td>{a.get('src_ip', '?')}</td>
<td>{a.get('dst_ip', '?')}</td>
<td class="mitre">{mitre[:50] if mitre else '-'}</td>
</tr>"""

    html = HTML_TEMPLATE.format(
        timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
        summary_cards=cards,
        severity_bars=bars,
        alert_rows=rows,
    )

    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"报告已生成: {output_path}")


def main():
    parser = argparse.ArgumentParser(description='NADS 告警 HTML 报告生成器')
    parser.add_argument('--alerts', type=str, help='告警 JSON 文件')
    parser.add_argument('--replay', type=str, help='回放 PCAP 并生成报告')
    parser.add_argument('--output', '-o', type=str,
                        default='./report.html', help='输出路径')
    args = parser.parse_args()

    if args.replay:
        from core.packet_capture import PacketCapture
        from core.misuse_detector import SignatureMatcher
        from core.alert_manager import AlertManager

        capture = PacketCapture(filter_rule='tcp')
        matcher = SignatureMatcher('./signatures')
        matcher.load_all()
        alert_mgr = AlertManager(enable_console=False, enable_json_export=False)

        def on_packet(pkt):
            try:
                from core.protocol_parser import ProtocolParser
                parser = ProtocolParser()
                parsed = parser.parse(pkt)
                if parsed and parsed.get('payload'):
                    for a in matcher.match_packet(parsed):
                        alert_mgr.submit(a, source='misuse')
            except Exception:
                pass

        capture.add_callback(on_packet)
        capture.replay_pcap(args.replay)

        alerts = [a.to_dict() for a in alert_mgr.alerts]
        generate_report(alerts, args.output)

    elif args.alerts:
        with open(args.alerts, 'r', encoding='utf-8') as f:
            alerts = json.load(f)
        generate_report(alerts, args.output)
    else:
        print("用法: --alerts <file.json> 或 --replay <file.pcap>")


if __name__ == '__main__':
    main()
