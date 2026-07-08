# ============================================================
# 模块: 协议解析器 (protocol_parser.py)
# 功能: 解析 TCP/IP 协议头，提取载荷数据，识别应用层协议
# 负责人: 成员B
# ============================================================

import struct
from typing import Optional, Dict, Any
from enum import Enum


class AppProtocol(Enum):
    """应用层协议枚举"""
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    SSH = "SSH"
    DNS = "DNS"
    FTP = "FTP"
    SMTP = "SMTP"
    TELNET = "TELNET"
    MYSQL = "MYSQL"
    TLS = "TLS"
    UNKNOWN = "UNKNOWN"


class ProtocolParser:
    """
    TCP/IP 数据包协议解析器

    功能:
    1. 解析 IP 头和 TCP 头
    2. 提取 TCP 载荷（应用层数据）
    3. 识别应用层协议类型
    4. 提取 HTTP 请求中的 URL、参数、Cookie 等字段（用于精细检测）

    使用示例:
        parser = ProtocolParser()
        result = parser.parse(packet_bytes)
        print(f"协议: {result['app_protocol']}, 载荷长度: {len(result['payload'])}")
    """

    # ─── 常用端口 → 协议映射 ───
    PORT_PROTO_MAP = {
        80:   AppProtocol.HTTP,
        443:  AppProtocol.HTTPS,   # 实际为 TLS 加密
        22:   AppProtocol.SSH,
        53:   AppProtocol.DNS,
        21:   AppProtocol.FTP,
        20:   AppProtocol.FTP,
        25:   AppProtocol.SMTP,
        587:  AppProtocol.SMTP,
        23:   AppProtocol.TELNET,
        3306: AppProtocol.MYSQL,
        8080: AppProtocol.HTTP,
        8443: AppProtocol.HTTPS,
    }

    # ─── 协议特征指纹 ───
    PROTO_FINGERPRINTS = [
        # (起始字节模式, 偏移, 协议)
        (b'GET ',       0, AppProtocol.HTTP),
        (b'POST ',      0, AppProtocol.HTTP),
        (b'HEAD ',      0, AppProtocol.HTTP),
        (b'PUT ',       0, AppProtocol.HTTP),
        (b'DELETE ',    0, AppProtocol.HTTP),
        (b'OPTIONS ',   0, AppProtocol.HTTP),
        (b'HTTP/',      0, AppProtocol.HTTP),
        (b'SSH-',       0, AppProtocol.SSH),
        (b'\x16\x03',   0, AppProtocol.TLS),  # TLS ClientHello / ServerHello
        (b'USER ',      0, AppProtocol.FTP),
        (b'220 ',       0, AppProtocol.FTP),
        (b'EHLO ',      0, AppProtocol.SMTP),
        (b'HELO ',      0, AppProtocol.SMTP),
    ]

    def __init__(self):
        self.parsed_count = 0  # 已解析包计数

    def parse(self, raw_packet: Any) -> Optional[Dict[str, Any]]:
        """
        解析数据包（支持 Scapy packet 对象或原始 bytes）

        Args:
            raw_packet: Scapy 捕获的 packet 对象，或原始字节

        Returns:
            dict: {
                'src_ip': str,         # 源 IP
                'dst_ip': str,         # 目标 IP
                'src_port': int,       # 源端口
                'dst_port': int,       # 目标端口
                'seq': int,            # TCP 序列号
                'ack': int,            # TCP 确认号
                'flags': int,          # TCP 标志位（原始值）
                'flags_str': str,      # TCP 标志位（可读字符串）
                'payload': bytes,      # 应用层载荷
                'payload_len': int,    # 载荷长度
                'app_protocol': AppProtocol,  # 应用层协议
                'timestamp': float,    # 时间戳
                # HTTP 专用字段（仅 HTTP 协议时有效）
                'http_method': str | None,
                'http_uri': str | None,
                'http_host': str | None,
                'http_user_agent': str | None,
            }
        """
        # 支持 Scapy 对象
        if hasattr(raw_packet, 'load'):
            return self._parse_scapy_packet(raw_packet)

        # 支持原始字节（需要手动解析 IP + TCP 头）
        if isinstance(raw_packet, (bytes, bytearray)):
            return self._parse_raw_bytes(bytes(raw_packet))

        return None

    def _parse_scapy_packet(self, pkt) -> Optional[Dict[str, Any]]:
        """解析 Scapy 捕获的 packet 对象"""
        try:
            from scapy.layers.inet import IP, TCP
            from scapy.layers.inet6 import IPv6
            from scapy.packet import Raw

            # 检查是否有 IP 层
            ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip_layer is None:
                return None

            # 检查是否有 TCP 层
            tcp_layer = pkt.getlayer(TCP)
            if tcp_layer is None:
                return None

            # 提取基础信息
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            seq = tcp_layer.seq
            ack = tcp_layer.ack
            flags = int(tcp_layer.flags)
            flags_str = str(tcp_layer.flags)

            # 提取载荷
            raw_layer = pkt.getlayer(Raw)
            payload = bytes(raw_layer.load) if raw_layer else b''

            # 识别应用层协议
            app_proto = self.identify_protocol_by_port(dst_port)
            if app_proto == AppProtocol.UNKNOWN:
                app_proto = self.identify_protocol_by_port(src_port)
            if payload:
                fp_proto = self.identify_protocol_by_fingerprint(payload)
                if fp_proto != AppProtocol.UNKNOWN:
                    app_proto = fp_proto

            result = {
                'src_ip':       src_ip,
                'dst_ip':       dst_ip,
                'src_port':     src_port,
                'dst_port':     dst_port,
                'seq':          seq,
                'ack':          ack,
                'flags':        flags,
                'flags_str':    flags_str,
                'payload':      payload,
                'payload_len':  len(payload),
                'app_protocol': app_proto,
                'timestamp':    float(pkt.time) if hasattr(pkt, 'time') else None,
                # HTTP 字段初始化
                'http_method':  None,
                'http_uri':     None,
                'http_host':    None,
                'http_user_agent': None,
            }

            # HTTP 深度解析
            if app_proto == AppProtocol.HTTP and payload:
                self._parse_http_fields(result, payload)

            self.parsed_count += 1
            return result

        except Exception as e:
            # 忽略解析失败的包
            return None

    def _parse_raw_bytes(self, data: bytes) -> Optional[Dict[str, Any]]:
        """
        从原始字节解析 IP/TCP 包（不依赖 Scapy）
        支持 IPv4 + TCP 的简化解析
        """
        if len(data) < 40:  # 最小 IP(20) + TCP(20) 头
            return None

        try:
            # IP 头解析
            version_ihl = data[0]
            version = version_ihl >> 4
            if version != 4:
                return None  # 仅支持 IPv4

            ihl = (version_ihl & 0x0F) * 4  # IP 头长度（字节）
            total_len = struct.unpack('!H', data[2:4])[0]
            src_ip = '.'.join(str(b) for b in data[12:16])
            dst_ip = '.'.join(str(b) for b in data[16:20])
            protocol = data[9]
            if protocol != 6:  # 仅处理 TCP
                return None

            # TCP 头解析（偏移 ihl）
            tcp_start = ihl
            if len(data) < tcp_start + 20:
                return None

            src_port = struct.unpack('!H', data[tcp_start:tcp_start+2])[0]
            dst_port = struct.unpack('!H', data[tcp_start+2:tcp_start+4])[0]
            seq = struct.unpack('!I', data[tcp_start+4:tcp_start+8])[0]
            ack = struct.unpack('!I', data[tcp_start+8:tcp_start+12])[0]
            data_offset = ((data[tcp_start+12] >> 4) & 0x0F) * 4
            flags = data[tcp_start+13]

            # 载荷
            payload_start = tcp_start + data_offset
            payload = data[payload_start:ihl + total_len - (ihl - 20)]

            return {
                'src_ip':      src_ip,
                'dst_ip':      dst_ip,
                'src_port':    src_port,
                'dst_port':    dst_port,
                'seq':         seq,
                'ack':         ack,
                'flags':       flags,
                'flags_str':   self._decode_flags(flags),
                'payload':     payload,
                'payload_len': len(payload),
                'app_protocol': AppProtocol.UNKNOWN,
                'timestamp':   None,
                'http_method': None,
                'http_uri':    None,
                'http_host':   None,
                'http_user_agent': None,
            }

        except Exception:
            return None

    # ─── 协议识别方法 ───

    def identify_protocol_by_port(self, port: int) -> AppProtocol:
        """根据端口号识别协议"""
        return self.PORT_PROTO_MAP.get(port, AppProtocol.UNKNOWN)

    def identify_protocol_by_fingerprint(self, payload: bytes) -> AppProtocol:
        """根据载荷指纹识别协议"""
        for pattern, offset, proto in self.PROTO_FINGERPRINTS:
            if len(payload) > offset and payload[offset:offset+len(pattern)] == pattern:
                return proto
        return AppProtocol.UNKNOWN

    # ─── HTTP 深度解析 ───

    def _parse_http_fields(self, result: Dict, payload: bytes) -> None:
        """从 HTTP 请求/响应中提取关键字段"""
        try:
            header_end = payload.find(b'\r\n\r\n')
            if header_end < 0:
                header_end = payload.find(b'\n\n')
            if header_end < 0:
                return

            headers = payload[:header_end].decode('utf-8', errors='ignore')
            lines = headers.split('\r\n') if '\r\n' in headers else headers.split('\n')

            # 请求行解析
            if lines:
                first = lines[0]
                parts = first.split(' ')
                if len(parts) >= 2:
                    method = parts[0].upper()
                    if method in ('GET', 'POST', 'HEAD', 'PUT', 'DELETE',
                                  'OPTIONS', 'PATCH', 'CONNECT', 'TRACE'):
                        result['http_method'] = method
                        result['http_uri'] = parts[1]

            # 首部字段解析
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    key_lower = key.strip().lower()
                    value = value.strip()
                    if key_lower == 'host':
                        result['http_host'] = value
                    elif key_lower == 'user-agent':
                        result['http_user_agent'] = value

        except Exception:
            pass

    # ─── 辅助方法 ───

    @staticmethod
    def _decode_flags(flags: int) -> str:
        """将 TCP flags 数值解码为可读字符串"""
        parts = []
        if flags & 0x01: parts.append('FIN')
        if flags & 0x02: parts.append('SYN')
        if flags & 0x04: parts.append('RST')
        if flags & 0x08: parts.append('PSH')
        if flags & 0x10: parts.append('ACK')
        if flags & 0x20: parts.append('URG')
        return '|'.join(parts) if parts else 'NONE'

    @staticmethod
    def is_syn_packet(flags: int) -> bool:
        """判断是否为 SYN 包（连接发起）"""
        return (flags & 0x02) != 0 and (flags & 0x10) == 0

    @staticmethod
    def is_syn_ack_packet(flags: int) -> bool:
        """判断是否为 SYN+ACK 包"""
        return (flags & 0x02) != 0 and (flags & 0x10) != 0

    @staticmethod
    def is_fin_packet(flags: int) -> bool:
        """判断是否为 FIN 包"""
        return (flags & 0x01) != 0

    @staticmethod
    def is_rst_packet(flags: int) -> bool:
        """判断是否为 RST 包"""
        return (flags & 0x04) != 0

    @staticmethod
    def get_flow_key(src_ip: str, dst_ip: str,
                     src_port: int, dst_port: int) -> tuple:
        """
        生成 TCP 流标识（四元组，双向归一化）
        同一流反方向的包会得到相同 key
        """
        if (src_ip, src_port) < (dst_ip, dst_port):
            return (src_ip, dst_ip, src_port, dst_port)
        else:
            return (dst_ip, src_ip, dst_port, src_port)

    @staticmethod
    def get_flow_key_directional(src_ip: str, dst_ip: str,
                                  src_port: int, dst_port: int) -> tuple:
        """生成方向敏感的流标识（用于区分客户端→服务器和反向流量）"""
        return (src_ip, dst_ip, src_port, dst_port)
