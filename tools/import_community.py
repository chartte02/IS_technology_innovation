#!/usr/bin/env python3
"""Generate 50 Suricata test rules + import them to NADS YAML"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

RULES = [
    # SQL Injection (6)
    'alert http any any -> any any (msg:"SQLi - Error Based extractvalue"; content:"extractvalue"; nocase; http_uri; classtype:web-application-attack; sid:1000101;)',
    'alert http any any -> any any (msg:"SQLi - Error Based updatexml"; content:"updatexml"; nocase; http_uri; classtype:web-application-attack; sid:1000102;)',
    'alert http any any -> any any (msg:"SQLi - Benchmark"; content:"benchmark"; nocase; http_uri; classtype:web-application-attack; sid:1000103;)',
    'alert http any any -> any any (msg:"SQLi - Order By Probe"; content:"order by"; nocase; http_uri; classtype:web-application-attack; sid:1000104;)',
    'alert http any any -> any any (msg:"SQLi - Having Clause"; content:"having"; nocase; http_uri; classtype:web-application-attack; sid:1000105;)',
    'alert http any any -> any any (msg:"SQLi - Group By"; content:"group by"; nocase; http_uri; classtype:web-application-attack; sid:1000106;)',
    # XSS (4)
    'alert http any any -> any any (msg:"XSS - Body Onerror"; content:"onerror"; nocase; http_uri; classtype:web-application-attack; sid:1000201;)',
    'alert http any any -> any any (msg:"XSS - SVG Onload"; content:"onload"; nocase; http_uri; classtype:web-application-attack; sid:1000202;)',
    'alert http any any -> any any (msg:"XSS - Document Cookie"; content:"document.cookie"; nocase; http_uri; classtype:web-application-attack; sid:1000203;)',
    'alert http any any -> any any (msg:"XSS - Eval Function"; content:"eval"; nocase; http_uri; classtype:web-application-attack; sid:1000204;)',
    # RCE (7)
    'alert http any any -> any any (msg:"RCE - Netcat"; content:"nc"; nocase; http_uri; classtype:web-application-attack; sid:1000301;)',
    'alert http any any -> any any (msg:"RCE - Curl"; content:"curl"; nocase; http_uri; classtype:web-application-attack; sid:1000302;)',
    'alert http any any -> any any (msg:"RCE - Wget"; content:"wget"; nocase; http_uri; classtype:web-application-attack; sid:1000303;)',
    'alert http any any -> any any (msg:"RCE - Powershell"; content:"powershell"; nocase; http_uri; classtype:web-application-attack; sid:1000304;)',
    'alert http any any -> any any (msg:"RCE - Cmd"; content:"cmd.exe"; nocase; http_uri; classtype:web-application-attack; sid:1000305;)',
    'alert http any any -> any any (msg:"RCE - Python"; content:"python -c"; nocase; http_uri; classtype:web-application-attack; sid:1000306;)',
    'alert http any any -> any any (msg:"RCE - Perl"; content:"perl -e"; nocase; http_uri; classtype:web-application-attack; sid:1000307;)',
    # File Inclusion (5)
    'alert http any any -> any any (msg:"LFI - Proc Self"; content:"/proc/self"; nocase; http_uri; classtype:web-application-attack; sid:1000401;)',
    'alert http any any -> any any (msg:"LFI - System32"; content:"system32"; nocase; http_uri; classtype:web-application-attack; sid:1000402;)',
    'alert http any any -> any any (msg:"LFI - PHP Wrapper"; content:"php://"; nocase; http_uri; classtype:web-application-attack; sid:1000403;)',
    'alert http any any -> any any (msg:"RFI - HTTP"; content:"http://"; nocase; http_uri; classtype:web-application-attack; sid:1000404;)',
    'alert http any any -> any any (msg:"RFI - FTP"; content:"ftp://"; nocase; http_uri; classtype:web-application-attack; sid:1000405;)',
    # Scanner (5)
    'alert http any any -> any any (msg:"Scan - DirBuster"; content:"dirbuster"; nocase; http_header; classtype:attempted-recon; sid:1000501;)',
    'alert http any any -> any any (msg:"Scan - Gobuster"; content:"gobuster"; nocase; http_header; classtype:attempted-recon; sid:1000502;)',
    'alert http any any -> any any (msg:"Scan - Wfuzz"; content:"wfuzz"; nocase; http_header; classtype:attempted-recon; sid:1000503;)',
    'alert http any any -> any any (msg:"Scan - Hydra"; content:"hydra"; nocase; http_header; classtype:attempted-recon; sid:1000504;)',
    'alert http any any -> any any (msg:"Scan - Medusa"; content:"medusa"; nocase; http_header; classtype:attempted-recon; sid:1000505;)',
    # C2 (3)
    'alert http any any -> any any (msg:"C2 - Empire Agent"; content:"empire"; nocase; http_header; classtype:trojan-activity; sid:1000601;)',
    'alert http any any -> any any (msg:"C2 - CobaltStrike"; content:"cobaltstrike"; nocase; http_header; classtype:trojan-activity; sid:1000602;)',
    'alert dns any any -> any any (msg:"C2 - DNS Tunnel"; content:"AAAA"; nocase; classtype:trojan-activity; sid:1000603;)',
    # Brute Force (3)
    'alert http any any -> any any (msg:"HTTP - WP Login"; content:"wp-login"; nocase; http_uri; classtype:attempted-admin; sid:1000703;)',
    # DoS (3)
    'alert http any any -> any any (msg:"DoS - Slowloris"; content:"X-a: b"; nocase; http_header; classtype:attempted-dos; sid:1000801;)',
    'alert http any any -> any any (msg:"DoS - Range Attack"; content:"Range: bytes"; nocase; http_header; classtype:attempted-dos; sid:1000802;)',
    'alert tcp any any -> any any (msg:"DoS - SYN Flood"; content:"SYN"; nocase; classtype:attempted-dos; sid:1000803;)',
    # WebShell (4)
    'alert http any any -> any any (msg:"WebShell - File Manager"; content:"filemanager"; nocase; http_uri; classtype:web-application-attack; sid:1000901;)',
    'alert http any any -> any any (msg:"WebShell - Backdoor"; content:"backdoor"; nocase; http_uri; classtype:web-application-attack; sid:1000902;)',
    'alert http any any -> any any (msg:"WebShell - Config"; content:"config.php"; nocase; http_uri; classtype:web-application-attack; sid:1000903;)',
    'alert http any any -> any any (msg:"WebShell - DB Dump"; content:"mysqldump"; nocase; http_uri; classtype:web-application-attack; sid:1000904;)',
    # Info Disclosure (5)
    'alert http any any -> any any (msg:"InfoLeak - Git"; content:".git/config"; nocase; http_uri; classtype:web-application-attack; sid:1001001;)',
    'alert http any any -> any any (msg:"InfoLeak - Env"; content:".env"; nocase; http_uri; classtype:web-application-attack; sid:1001002;)',
    'alert http any any -> any any (msg:"InfoLeak - Swagger"; content:"swagger"; nocase; http_uri; classtype:web-application-attack; sid:1001003;)',
    'alert http any any -> any any (msg:"InfoLeak - PHPInfo"; content:"phpinfo"; nocase; http_uri; classtype:web-application-attack; sid:1001004;)',
    'alert http any any -> any any (msg:"InfoLeak - Debug"; content:"debug"; nocase; http_uri; classtype:web-application-attack; sid:1001005;)',
]

from tools.suricata_importer import SuricataImporter

# Write rules file
rules_path = os.path.join(os.path.dirname(__file__), 'community_sample.rules')
with open(rules_path, 'w') as f:
    f.write('\n'.join(RULES))

# Import
importer = SuricataImporter()
count = importer.parse_file(rules_path)
print(f"Parsed: {count}/{len(RULES)} rules")

# Export
out = importer.export_yaml('./signatures', filename='imported_community.yaml')
print(f"Exported: {out}")

# Verify loading
from core.misuse_detector import SignatureMatcher
m = SignatureMatcher('./signatures')
total = m.load_all()
stats = m.get_statistics()
print(f"Total rules now: {total}")
for cat, n in sorted(stats['by_category'].items()):
    print(f"  {cat}: {n}")
