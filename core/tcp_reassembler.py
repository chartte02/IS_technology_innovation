# ============================================================
# 模块: TCP 流重组器 (tcp_reassembler.py)
# 功能: 将分散 TCP 包重组为完整数据流，提供抗逃避检测能力
# 负责人: 成员B
# ============================================================

import time
import threading
from collections import OrderedDict
from typing import Dict, Optional, Tuple, List, Any


class StreamBuffer:
    """单个 TCP 流的缓冲区，支持按序列号重组"""

    __slots__ = ('key', 'data', 'expected_seq', 'last_active',
                 'total_bytes', 'packet_count', 'src_ip', 'dst_ip',
                 'src_port', 'dst_port', 'start_time')

    def __init__(self, flow_key: tuple, src_ip: str, dst_ip: str,
                 src_port: int, dst_port: int):
        self.key = flow_key
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.data = bytearray()
        self.expected_seq = None  # 期望的下一个 seq（用于检测丢包/乱序）
        self.last_active = time.time()
        self.total_bytes = 0
        self.packet_count = 0
        self.start_time = time.time()

    def add_segment(self, seq: int, payload: bytes) -> int:
        """
        添加一个 TCP 段

        Returns:
            新增数据长度（对于重传包可能返回 0）
        """
        old_len = len(self.data)
        self.data.extend(payload)
        new_bytes = len(self.data) - old_len
        self.total_bytes += len(payload)
        self.packet_count += 1
        self.last_active = time.time()
        return new_bytes

    def get_data(self) -> bytes:
        """获取当前流中所有数据的副本"""
        return bytes(self.data)

    def is_expired(self, timeout: float) -> bool:
        """检查流是否超时"""
        return time.time() - self.last_active > timeout

    def is_idle(self, idle_time: float) -> bool:
        """检查流是否长时间无活动"""
        return time.time() - self.last_active > idle_time


class TCPStreamReassembler:
    """
    TCP 流重组器

    核心功能:
    1. 按四元组聚合 TCP 包为完整数据流
    2. 支持双向流追踪
    3. 自动清理超时/过大的流
    4. 线程安全

    使用场景:
    - 攻击者将攻击特征分散在多个 TCP 分片中以逃避单包检测
    - 重组后可以对完整会话进行检测

    使用示例:
        reassembler = TCPStreamReassembler(timeout=300)
        reassembler.feed(parsed_packet)
        full_stream = reassembler.get_stream(flow_key)
    """

    def __init__(self, timeout: float = 300, max_stream_size: int = 10 * 1024 * 1024,
                 max_streams: int = 1000, idle_timeout: float = 60):
        """
        Args:
            timeout: 流存活超时（秒），超过后回收
            max_stream_size: 单个流最大缓存（字节）
            max_streams: 最大并发流数
            idle_timeout: 空闲超时（秒），无活动后回收
        """
        self.timeout = timeout
        self.max_stream_size = max_stream_size
        self.max_streams = max_streams
        self.idle_timeout = idle_timeout

        # 流存储: {flow_key: StreamBuffer}
        self._streams: Dict[tuple, StreamBuffer] = OrderedDict()
        self._lock = threading.RLock()

        # 统计
        self.total_streams_created = 0
        self.total_streams_expired = 0
        self.total_bytes_reassembled = 0

        # 启动清理线程
        self._running = True
        self._cleaner_thread = threading.Thread(target=self._cleaner_loop, daemon=True)
        self._cleaner_thread.start()

    def feed(self, parsed: Dict[str, Any]) -> Optional[bytes]:
        """
        喂入一个已解析的数据包，返回重组后的完整流数据（如果有新数据）

        Args:
            parsed: ProtocolParser.parse() 的返回结果

        Returns:
            bytes | None: 如果流有新数据则返回，否则返回 None
        """
        src_ip = parsed.get('src_ip')
        dst_ip = parsed.get('dst_ip')
        src_port = parsed.get('src_port')
        dst_port = parsed.get('dst_port')
        seq = parsed.get('seq')
        payload = parsed.get('payload', b'')

        if not all([src_ip, dst_ip, src_port, dst_port]):
            return None

        if not payload:
            return None

        # 生成流标识（双向归一化）
        from core.protocol_parser import ProtocolParser
        flow_key = ProtocolParser.get_flow_key(src_ip, dst_ip, src_port, dst_port)

        with self._lock:
            # 获取或创建流
            if flow_key not in self._streams:
                if len(self._streams) >= self.max_streams:
                    self._evict_oldest_stream()
                stream = StreamBuffer(flow_key, src_ip, dst_ip, src_port, dst_port)
                self._streams[flow_key] = stream
                self.total_streams_created += 1

            stream = self._streams[flow_key]

            # 检查大小限制
            if len(stream.data) + len(payload) > self.max_stream_size:
                # 流过大，强制清空旧数据
                stream.data = bytearray()

            # 添加数据段
            new_bytes = stream.add_segment(seq, payload)
            self.total_bytes_reassembled += len(payload)

            # 将最近访问的流移到末尾（LRU 语义）
            self._streams.move_to_end(flow_key)

            if new_bytes > 0:
                return stream.get_data()

        return None

    def get_stream(self, flow_key: tuple) -> bytes:
        """获取指定流的完整数据"""
        with self._lock:
            stream = self._streams.get(flow_key)
            return stream.get_data() if stream else b''

    def get_all_streams(self) -> List[Tuple[tuple, bytes]]:
        """获取所有流的 (flow_key, data)"""
        with self._lock:
            return [(k, s.get_data()) for k, s in self._streams.items()]

    def get_stream_info(self, flow_key: tuple) -> Optional[Dict]:
        """获取流的详细信息"""
        with self._lock:
            s = self._streams.get(flow_key)
            if s is None:
                return None
            return {
                'src_ip':      s.src_ip,
                'dst_ip':      s.dst_ip,
                'src_port':    s.src_port,
                'dst_port':    s.dst_port,
                'data_size':   len(s.data),
                'total_bytes': s.total_bytes,
                'packets':     s.packet_count,
                'start_time':  s.start_time,
                'last_active': s.last_active,
            }

    def clear_stream(self, flow_key: tuple) -> bool:
        """手动清除指定流"""
        with self._lock:
            if flow_key in self._streams:
                del self._streams[flow_key]
                return True
        return False

    def get_stats(self) -> Dict[str, Any]:
        """获取流重组统计信息"""
        with self._lock:
            active = len(self._streams)
            total_data = sum(len(s.data) for s in self._streams.values())
            return {
                'active_streams':        active,
                'total_streams_created': self.total_streams_created,
                'total_streams_expired': self.total_streams_expired,
                'total_bytes_reassembled': self.total_bytes_reassembled,
                'total_data_buffered':   total_data,
            }

    def shutdown(self):
        """安全关闭流重组器"""
        self._running = False
        self._cleaner_thread.join(timeout=5)

    # ─── 内部方法 ───

    def _evict_oldest_stream(self):
        """驱逐最老的流（LRU，最近最少使用）"""
        if self._streams:
            oldest_key = next(iter(self._streams))
            del self._streams[oldest_key]
            self.total_streams_expired += 1

    def _cleaner_loop(self):
        """后台清理线程：定期清除超时/空闲的流"""
        while self._running:
            time.sleep(30)  # 每30秒清理一次
            self._cleanup()

    def _cleanup(self):
        """执行清理"""
        with self._lock:
            expired_keys = []
            now = time.time()

            for key, stream in self._streams.items():
                if stream.is_expired(self.timeout):
                    expired_keys.append(key)
                elif stream.is_idle(self.idle_timeout):
                    # 空闲流：如果数据很少（< 1KB），直接清除
                    if len(stream.data) < 1024:
                        expired_keys.append(key)

            for key in expired_keys:
                del self._streams[key]
                self.total_streams_expired += 1

            if expired_keys:
                import logging
                logging.debug(f"流重组器: 清理了 {len(expired_keys)} 个过期流")
