#!/usr/bin/env python3
# ============================================================
# 模块: 动态流量生成器 (traffic_generator.py)
# 功能: 在后台线程持续生成攻击+正常混合流量, 模拟实时攻击场景
# 负责人: 成员D
# ============================================================

import time
import random
import threading
from scapy.all import IP, TCP, Raw

# ─── 攻击载荷库 (7 大类, 对应 93 条特征规则) ───

SQLI_PAYLOADS = [
    b"GET /page.php?id=1 UNION SELECT user,password FROM users HTTP/1.1\r\nHost: target.com\r\n\r\n",
    b"GET /login.php?user=admin' OR '1'='1'-- HTTP/1.1\r\nHost: target.com\r\n\r\n",
    b"GET /search?q=1; DROP TABLE users;-- HTTP/1.1\r\nHost: target.com\r\n\r\n",
    b"GET /api?param=1 AND SLEEP(5)-- HTTP/1.1\r\nHost: target.com\r\n\r\n",
    b"GET /admin?user=admin'-- HTTP/1.1\r\nUser-Agent: sqlmap/1.6#stable\r\nHost: target.com\r\n\r\n",
    b"GET /profile?id=1 UNION ALL SELECT 1,2,3,4,5 HTTP/1.1\r\nHost: target.com\r\n\r\n",
    b"GET /catalog?cat=1' UNION SELECT 1,@@version,3-- HTTP/1.1\r\nHost: target.com\r\n\r\n",
]

XSS_PAYLOADS = [
    b"GET /search?q=<script>alert(1)</script> HTTP/1.1\r\nHost: target.com\r\n\r\n",
    b"GET /comment?text=<img src=x onerror=alert(document.cookie)> HTTP/1.1\r\nHost: target.com\r\n\r\n",
    b"GET /page?x=<svg onload=alert(1)> HTTP/1.1\r\nHost: target.com\r\n\r\n",
    b"GET /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1\r\nHost: target.com\r\n\r\n",
]

WEB_ATTACK_PAYLOADS = [
    b"GET /../../etc/passwd HTTP/1.1\r\nHost: target.com\r\n\r\n",
    b"GET /ping?ip=127.0.0.1|cat /etc/passwd HTTP/1.1\r\nHost: target.com\r\n\r\n",
    b"GET /c99shell.php HTTP/1.1\r\nHost: target.com\r\n\r\n",
    b"GET /eval?code=system('id') HTTP/1.1\r\nHost: target.com\r\n\r\n",
]

BRUTEFORCE_PAYLOADS = [
    b"Failed password for root from 10.0.0.88 port 22 ssh2",
    b"Failed password for admin from 10.0.0.99 port 22 ssh2",
    b"530 Login incorrect.\r\n",
]

BACKDOOR_PAYLOADS = [
    b"GET /shell.php?cmd=whoami HTTP/1.1\r\nHost: target.com\r\nUser-Agent: AntSword/v2.1\r\n\r\n",
    b"GET /upload/evil.jsp?pwd=cmd&action=exec HTTP/1.1\r\nHost: target.com\r\n\r\n",
    b"GET /include/eval.php?<?=eval($_POST[1]);?> HTTP/1.1\r\nHost: target.com\r\n\r\n",
]

NORMAL_PAYLOADS = [
    b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
    b"GET /about.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
    b"GET /style.css HTTP/1.1\r\nHost: example.com\r\nReferer: https://example.com/\r\n\r\n",
    b"GET /api/status HTTP/1.1\r\nHost: example.com\r\n\r\n",
    b"POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 27\r\n\r\nuser=admin&pass=password123",
]

# ─── IP 池 ───

ATTACKER_IPS = ["10.0.0.55","10.0.0.77","10.0.0.88","10.0.0.99",
                "192.168.1.100","192.168.1.200","172.16.0.50","172.16.0.66"]
TARGET_IPS  = ["192.168.1.1","192.168.1.10","10.0.0.1"]

# 类别权重 (攻击 60% / 正常 40%)
CATEGORY_WEIGHTS = {
    "sqli": 15, "xss": 12, "web_attack": 12,
    "bruteforce": 8, "backdoor": 8, "scan": 5,
    "normal": 40,
}

PORT_MAP = {
    "sqli": 80, "xss": 80, "web_attack": 80,
    "bruteforce": 22, "backdoor": 8080, "scan": None, "normal": 80,
}


class TrafficGenerator:
    """后台线程持续生成混合攻击流量, 注入 IDS 检测流水线"""

    def __init__(self, engine):
        self.engine = engine
        self._running = False
        self._paused = False
        self._thread = None
        self._sent = 0
        self._attacks = 0
        self._normals = 0

    @property
    def is_running(self):
        return self._running and not self._paused

    def start(self, pps: float = 3.0):
        if self._running:
            return
        self._running = True
        self._paused = False
        self._sent = self._attacks = self._normals = 0
        self._thread = threading.Thread(target=self._loop, args=(pps,), daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)

    def pause(self):
        self._paused = True

    def resume(self):
        self._paused = False

    def get_stats(self):
        return {"sent": self._sent, "attacks": self._attacks, "normals": self._normals}

    # ─── 内部 ───

    def _pick(self):
        cats = list(CATEGORY_WEIGHTS)
        w = list(CATEGORY_WEIGHTS.values())
        cat = random.choices(cats, weights=w, k=1)[0]
        pool = {"sqli": SQLI_PAYLOADS, "xss": XSS_PAYLOADS,
                "web_attack": WEB_ATTACK_PAYLOADS, "bruteforce": BRUTEFORCE_PAYLOADS,
                "backdoor": BACKDOOR_PAYLOADS}.get(cat, NORMAL_PAYLOADS)
        return cat, random.choice(pool)

    def _loop(self, pps):
        interval = 1.0 / max(pps, 0.1)
        scan_ports = list(range(1, 30))

        while self._running:
            if self._paused:
                time.sleep(0.1)
                continue

            cat, payload = self._pick()
            src = random.choice(ATTACKER_IPS)
            dst = random.choice(TARGET_IPS)
            sport = random.randint(30000, 60000)
            dport = PORT_MAP.get(cat, 80)
            if dport is None:  # scan: 轮流换端口
                dport = scan_ports[self._sent % len(scan_ports)]

            pkt = IP(src=src, dst=dst) / TCP(
                sport=sport, dport=dport, flags="PA",
                seq=random.randint(1, 0xFFFFFFFF)) / Raw(load=payload)

            try:
                self.engine._on_packet(pkt)
            except Exception:
                pass

            self._sent += 1
            if cat != "normal":
                self._attacks += 1
            else:
                self._normals += 1

            time.sleep(interval)
