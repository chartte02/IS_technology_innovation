# ============================================================
# Module: Application protocol parser (protocol_parser.py)
# Owner: Member B
# ============================================================

import struct
from enum import Enum
from typing import Any, Dict, Optional


class AppProtocol(Enum):
    """Application-layer protocol labels used by downstream modules."""

    HTTP = "HTTP"
    HTTPS = "HTTPS"
    SSH = "SSH"
    DNS = "DNS"
    FTP = "FTP"
    SMTP = "SMTP"
    POP3 = "POP3"
    IMAP = "IMAP"
    REDIS = "REDIS"
    MONGODB = "MONGODB"
    TELNET = "TELNET"
    MYSQL = "MYSQL"
    TLS = "TLS"
    UNKNOWN = "UNKNOWN"


class ProtocolParser:
    """Parse IP/TCP headers, payloads, and common application protocols."""

    PORT_PROTO_MAP = {
        80: AppProtocol.HTTP,
        8080: AppProtocol.HTTP,
        443: AppProtocol.HTTPS,
        8443: AppProtocol.HTTPS,
        22: AppProtocol.SSH,
        53: AppProtocol.DNS,
        20: AppProtocol.FTP,
        21: AppProtocol.FTP,
        25: AppProtocol.SMTP,
        465: AppProtocol.SMTP,
        587: AppProtocol.SMTP,
        110: AppProtocol.POP3,
        995: AppProtocol.POP3,
        143: AppProtocol.IMAP,
        993: AppProtocol.IMAP,
        6379: AppProtocol.REDIS,
        27017: AppProtocol.MONGODB,
        27018: AppProtocol.MONGODB,
        27019: AppProtocol.MONGODB,
        23: AppProtocol.TELNET,
        3306: AppProtocol.MYSQL,
    }

    PROTO_FINGERPRINTS = [
        (b"GET ", 0, AppProtocol.HTTP),
        (b"POST ", 0, AppProtocol.HTTP),
        (b"HEAD ", 0, AppProtocol.HTTP),
        (b"PUT ", 0, AppProtocol.HTTP),
        (b"DELETE ", 0, AppProtocol.HTTP),
        (b"OPTIONS ", 0, AppProtocol.HTTP),
        (b"PATCH ", 0, AppProtocol.HTTP),
        (b"HTTP/", 0, AppProtocol.HTTP),
        (b"SSH-", 0, AppProtocol.SSH),
        (b"\x16\x03", 0, AppProtocol.TLS),
        (b"EHLO ", 0, AppProtocol.SMTP),
        (b"HELO ", 0, AppProtocol.SMTP),
        (b"MAIL FROM:", 0, AppProtocol.SMTP),
        (b"RCPT TO:", 0, AppProtocol.SMTP),
        (b"DATA\r\n", 0, AppProtocol.SMTP),
        (b"+OK", 0, AppProtocol.POP3),
        (b"-ERR", 0, AppProtocol.POP3),
        (b"CAPA\r\n", 0, AppProtocol.POP3),
        (b"* CAPABILITY", 0, AppProtocol.IMAP),
        (b"CAPABILITY", 0, AppProtocol.IMAP),
        (b"LOGIN ", 0, AppProtocol.IMAP),
        (b"* OK", 0, AppProtocol.IMAP),
        (b"*1\r\n$4\r\nPING", 0, AppProtocol.REDIS),
        (b"*2\r\n$4\r\nAUTH", 0, AppProtocol.REDIS),
        (b"+PONG", 0, AppProtocol.REDIS),
        (b"-NOAUTH", 0, AppProtocol.REDIS),
        (b"USER ", 0, AppProtocol.FTP),
        (b"220 ", 0, AppProtocol.FTP),
    ]

    def __init__(self):
        self.parsed_count = 0

    def parse(self, raw_packet: Any) -> Optional[Dict[str, Any]]:
        """Parse a Scapy packet object or raw IPv4/TCP bytes."""
        if hasattr(raw_packet, "getlayer"):
            return self._parse_scapy_packet(raw_packet)

        if isinstance(raw_packet, (bytes, bytearray)):
            return self._parse_raw_bytes(bytes(raw_packet))

        return None

    def _parse_scapy_packet(self, pkt) -> Optional[Dict[str, Any]]:
        try:
            from scapy.layers.inet import IP, TCP
            from scapy.layers.inet6 import IPv6
            from scapy.packet import Raw

            ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip_layer is None:
                return None

            tcp_layer = pkt.getlayer(TCP)
            if tcp_layer is None:
                return None

            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            seq = tcp_layer.seq
            ack = tcp_layer.ack
            flags = int(tcp_layer.flags)
            flags_str = str(tcp_layer.flags)

            raw_layer = pkt.getlayer(Raw)
            payload = bytes(raw_layer.load) if raw_layer else b""
            app_proto = self._identify_app_protocol(payload, src_port, dst_port)

            result = self._build_result(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                seq=seq,
                ack=ack,
                flags=flags,
                flags_str=flags_str,
                payload=payload,
                app_proto=app_proto,
                timestamp=float(pkt.time) if hasattr(pkt, "time") else None,
            )

            if app_proto == AppProtocol.HTTP and payload:
                self._parse_http_fields(result, payload)

            self.parsed_count += 1
            return result

        except Exception:
            return None

    def _parse_raw_bytes(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse simplified raw IPv4 + TCP bytes without Scapy."""
        if len(data) < 40:
            return None

        try:
            version_ihl = data[0]
            version = version_ihl >> 4
            if version != 4:
                return None

            ihl = (version_ihl & 0x0F) * 4
            total_len = struct.unpack("!H", data[2:4])[0]
            src_ip = ".".join(str(b) for b in data[12:16])
            dst_ip = ".".join(str(b) for b in data[16:20])
            protocol = data[9]
            if protocol != 6:
                return None

            tcp_start = ihl
            if len(data) < tcp_start + 20:
                return None

            src_port = struct.unpack("!H", data[tcp_start:tcp_start + 2])[0]
            dst_port = struct.unpack("!H", data[tcp_start + 2:tcp_start + 4])[0]
            seq = struct.unpack("!I", data[tcp_start + 4:tcp_start + 8])[0]
            ack = struct.unpack("!I", data[tcp_start + 8:tcp_start + 12])[0]
            data_offset = ((data[tcp_start + 12] >> 4) & 0x0F) * 4
            flags = data[tcp_start + 13]

            payload_start = tcp_start + data_offset
            payload_end = min(len(data), total_len)
            payload = data[payload_start:payload_end]
            app_proto = self._identify_app_protocol(payload, src_port, dst_port)

            result = self._build_result(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                seq=seq,
                ack=ack,
                flags=flags,
                flags_str=self._decode_flags(flags),
                payload=payload,
                app_proto=app_proto,
                timestamp=None,
            )

            if app_proto == AppProtocol.HTTP and payload:
                self._parse_http_fields(result, payload)

            self.parsed_count += 1
            return result

        except Exception:
            return None

    def _build_result(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        seq: int,
        ack: int,
        flags: int,
        flags_str: str,
        payload: bytes,
        app_proto: AppProtocol,
        timestamp: Optional[float],
    ) -> Dict[str, Any]:
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "seq": seq,
            "ack": ack,
            "flags": flags,
            "flags_str": flags_str,
            "payload": payload,
            "payload_len": len(payload),
            "app_protocol": app_proto,
            "timestamp": timestamp,
            "http_method": None,
            "http_uri": None,
            "http_host": None,
            "http_user_agent": None,
        }

    def _identify_app_protocol(
        self,
        payload: bytes,
        src_port: Optional[int],
        dst_port: Optional[int],
    ) -> AppProtocol:
        app_proto = self.identify_protocol_by_port(dst_port or 0)
        if app_proto == AppProtocol.UNKNOWN:
            app_proto = self.identify_protocol_by_port(src_port or 0)

        if payload:
            fp_proto = self.identify_protocol_by_fingerprint(payload, src_port, dst_port)
            if fp_proto != AppProtocol.UNKNOWN:
                app_proto = fp_proto

        return app_proto

    def identify_protocol_by_port(self, port: int) -> AppProtocol:
        """Identify a protocol by well-known TCP port."""
        return self.PORT_PROTO_MAP.get(port, AppProtocol.UNKNOWN)

    def identify_protocol_by_fingerprint(
        self,
        payload: bytes,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
    ) -> AppProtocol:
        """Identify a protocol by payload fingerprint."""
        if not payload:
            return AppProtocol.UNKNOWN

        port_proto = self.identify_protocol_by_port(dst_port or 0)
        if port_proto == AppProtocol.UNKNOWN:
            port_proto = self.identify_protocol_by_port(src_port or 0)

        upper_payload = payload[:64].upper()

        if port_proto == AppProtocol.POP3 and upper_payload.startswith(
            (b"USER ", b"PASS ", b"CAPA", b"+OK", b"-ERR")
        ):
            return AppProtocol.POP3

        if port_proto == AppProtocol.FTP and upper_payload.startswith(
            (b"USER ", b"PASS ", b"220 ", b"331 ", b"230 ")
        ):
            return AppProtocol.FTP

        if port_proto == AppProtocol.IMAP and (
            b"CAPABILITY" in upper_payload
            or b"LOGIN" in upper_payload
            or upper_payload.startswith(b"* OK")
        ):
            return AppProtocol.IMAP

        if self._looks_like_mongodb(payload):
            return AppProtocol.MONGODB

        for pattern, offset, proto in self.PROTO_FINGERPRINTS:
            if len(payload) >= offset + len(pattern):
                candidate = payload[offset:offset + len(pattern)]
                if candidate.upper() == pattern.upper():
                    return proto

        return AppProtocol.UNKNOWN

    @staticmethod
    def _looks_like_mongodb(payload: bytes) -> bool:
        """Recognize a MongoDB wire protocol message header."""
        if len(payload) < 16:
            return False

        message_length, _, _, op_code = struct.unpack("<iiii", payload[:16])
        known_op_codes = {
            1,
            1000,
            2001,
            2002,
            2003,
            2004,
            2005,
            2006,
            2007,
            2010,
            2011,
            2012,
            2013,
        }
        return 16 <= message_length <= len(payload) and op_code in known_op_codes

    def _parse_http_fields(self, result: Dict[str, Any], payload: bytes) -> None:
        """Extract common HTTP request fields for signature matching."""
        try:
            header_end = payload.find(b"\r\n\r\n")
            if header_end < 0:
                header_end = payload.find(b"\n\n")
            if header_end < 0:
                return

            headers = payload[:header_end].decode("utf-8", errors="ignore")
            lines = headers.split("\r\n") if "\r\n" in headers else headers.split("\n")

            if lines:
                first = lines[0]
                parts = first.split(" ")
                if len(parts) >= 2:
                    method = parts[0].upper()
                    if method in (
                        "GET",
                        "POST",
                        "HEAD",
                        "PUT",
                        "DELETE",
                        "OPTIONS",
                        "PATCH",
                        "CONNECT",
                        "TRACE",
                    ):
                        result["http_method"] = method
                        result["http_uri"] = parts[1]

            for line in lines[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    key_lower = key.strip().lower()
                    value = value.strip()
                    if key_lower == "host":
                        result["http_host"] = value
                    elif key_lower == "user-agent":
                        result["http_user_agent"] = value

        except Exception:
            pass

    @staticmethod
    def _decode_flags(flags: int) -> str:
        parts = []
        if flags & 0x01:
            parts.append("FIN")
        if flags & 0x02:
            parts.append("SYN")
        if flags & 0x04:
            parts.append("RST")
        if flags & 0x08:
            parts.append("PSH")
        if flags & 0x10:
            parts.append("ACK")
        if flags & 0x20:
            parts.append("URG")
        return "|".join(parts) if parts else "NONE"

    @staticmethod
    def is_syn_packet(flags: int) -> bool:
        return (flags & 0x02) != 0 and (flags & 0x10) == 0

    @staticmethod
    def is_syn_ack_packet(flags: int) -> bool:
        return (flags & 0x02) != 0 and (flags & 0x10) != 0

    @staticmethod
    def is_fin_packet(flags: int) -> bool:
        return (flags & 0x01) != 0

    @staticmethod
    def is_rst_packet(flags: int) -> bool:
        return (flags & 0x04) != 0

    @staticmethod
    def get_flow_key(src_ip: str, dst_ip: str,
                     src_port: int, dst_port: int) -> tuple:
        """Return a normalized bidirectional TCP flow key."""
        if (src_ip, src_port) < (dst_ip, dst_port):
            return (src_ip, dst_ip, src_port, dst_port)
        return (dst_ip, src_ip, dst_port, src_port)

    @staticmethod
    def get_flow_key_directional(src_ip: str, dst_ip: str,
                                  src_port: int, dst_port: int) -> tuple:
        """Return a directional TCP flow key."""
        return (src_ip, dst_ip, src_port, dst_port)
