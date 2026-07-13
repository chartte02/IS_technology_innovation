#!/usr/bin/env python3
"""告警格式导出 — CEF (ArcSight Common Event Format) + Syslog"""
import sys, os, json, argparse
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

SEVERITY_MAP = {'critical': 10, 'high': 8, 'medium': 5, 'low': 3, 'info': 1}

def alert_to_cef(alert: dict) -> str:
    """Convert alert to CEF format"""
    sev = SEVERITY_MAP.get(alert.get('severity', 'medium'), 5)
    header = (
        f"CEF:0|NADS|IDS|1.0|{alert.get('signature_id','?')}"
        f"|{alert.get('signature_name','?')}|{sev}"
    )
    extensions = (
        f"src={alert.get('src_ip','?')} "
        f"dst={alert.get('dst_ip','?')} "
        f"spt={alert.get('src_port','?')} "
        f"dpt={alert.get('dst_port','?')} "
        f"cat={alert.get('category','?')} "
        f"msg={alert.get('description','?')[:200]} "
        f"cs1={alert.get('matched_pattern','?')[:100]} "
        f"cs2Label=MITRE cs2={alert.get('mitre_technique','?')}"
    )
    return f"{header}|{extensions}"


def alert_to_syslog(alert: dict) -> str:
    """Convert alert to syslog-like format"""
    import time as _time
    ts = alert.get('timestamp', _time.time())
    tstr = _time.strftime('%b %d %H:%M:%S', _time.localtime(ts))
    severity = alert.get('severity', 'medium').upper()
    return (
        f"{tstr} NADS [{severity}] {alert.get('signature_id','?')}: "
        f"{alert.get('description','?')[:150]} "
        f"[src={alert.get('src_ip','?')} dst={alert.get('dst_ip','?')}]"
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--replay', type=str, help='PCAP file to replay')
    parser.add_argument('--alerts', type=str, help='alerts.json file')
    parser.add_argument('--format', choices=['cef', 'syslog', 'both'],
                        default='both')
    parser.add_argument('--output', '-o', type=str, help='output file')
    args = parser.parse_args()

    alerts_data = []

    if args.replay:
        from core.packet_capture import PacketCapture
        from core.misuse_detector import SignatureMatcher
        from core.alert_manager import AlertManager

        matcher = SignatureMatcher('./signatures')
        matcher.load_all()
        alert_mgr = AlertManager(enable_console=False, enable_json_export=False)

        def on_pkt(pkt):
            try:
                from core.protocol_parser import ProtocolParser
                parsed = ProtocolParser().parse(pkt)
                if parsed and parsed.get('payload'):
                    for a in matcher.match_packet(parsed):
                        alert_mgr.submit(a, source='misuse')
            except Exception:
                pass

        capture = PacketCapture()
        capture.add_callback(on_pkt)
        capture.replay_pcap(args.replay)
        alerts_data = [a.to_dict() for a in alert_mgr.alerts]

    elif args.alerts:
        with open(args.alerts, 'r', encoding='utf-8') as f:
            alerts_data = json.load(f)
    else:
        print("Usage: --replay <pcap> or --alerts <json>")
        return

    lines = []
    for alert in alerts_data:
        if args.format in ('cef', 'both'):
            lines.append(alert_to_cef(alert))
        if args.format in ('syslog', 'both'):
            lines.append(alert_to_syslog(alert))

    output = '\n'.join(lines)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"Exported {len(alerts_data)} alerts to {args.output} ({args.format})")
    else:
        print(f"=== {len(alerts_data)} alerts ({args.format}) ===")
        for line in lines[:10]:
            print(line[:150])
        if len(lines) > 10:
            print(f"... and {len(lines)-10} more")


if __name__ == '__main__':
    main()
