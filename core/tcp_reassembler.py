# ============================================================
# Module: TCP stream reassembler (tcp_reassembler.py)
# Owner: Member B
# ============================================================

import threading
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple


class StreamBuffer:
    """Buffer for one directional TCP byte stream.

    The buffer reassembles payload strictly by TCP sequence number:
    - in-order segments are appended immediately
    - out-of-order segments are cached until the missing gap arrives
    - full retransmissions are ignored
    - partial overlaps are trimmed before appending
    """

    __slots__ = (
        "key",
        "data",
        "segments",
        "data_start_seq",
        "expected_seq",
        "last_active",
        "total_bytes",
        "packet_count",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "start_time",
        "out_of_order_count",
        "retransmission_count",
        "duplicate_bytes",
        "overlap_bytes",
        "gap_count",
    )

    def __init__(self, flow_key: tuple, src_ip: str, dst_ip: str,
                 src_port: int, dst_port: int):
        self.key = flow_key
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.data = bytearray()
        self.segments: Dict[int, bytes] = {}
        self.data_start_seq: Optional[int] = None
        self.expected_seq: Optional[int] = None
        self.last_active = time.time()
        self.total_bytes = 0
        self.packet_count = 0
        self.start_time = time.time()
        self.out_of_order_count = 0
        self.retransmission_count = 0
        self.duplicate_bytes = 0
        self.overlap_bytes = 0
        self.gap_count = 0

    def add_segment(self, seq: int, payload: bytes) -> int:
        """Add a TCP segment and return newly reassembled byte count."""
        if seq is None or not payload:
            return 0

        self.total_bytes += len(payload)
        self.packet_count += 1
        self.last_active = time.time()

        if self.expected_seq is None:
            self.data_start_seq = seq
            self.expected_seq = seq

        if self.data_start_seq is not None and seq < self.data_start_seq:
            added = self._prepend_before_start(seq, payload)
            added += self._flush_contiguous_segments()
            return added

        if seq < self.expected_seq:
            overlap = self.expected_seq - seq
            if overlap >= len(payload):
                self.retransmission_count += 1
                self.duplicate_bytes += len(payload)
                return 0
            self.overlap_bytes += overlap
            payload = payload[overlap:]
            seq = self.expected_seq

        if seq > self.expected_seq:
            self._buffer_out_of_order(seq, payload)
            return 0

        added = self._append_in_order(payload)
        added += self._flush_contiguous_segments()
        return added

    def get_data(self) -> bytes:
        """Return a copy of the currently reassembled stream data."""
        return bytes(self.data)

    def clear_data(self) -> None:
        """Clear reassembled data and queued out-of-order segments."""
        self.data = bytearray()
        self.segments.clear()
        self.data_start_seq = None
        self.expected_seq = None

    def is_expired(self, timeout: float) -> bool:
        """Return whether the stream exceeded its lifetime timeout."""
        return time.time() - self.last_active > timeout

    def is_idle(self, idle_time: float) -> bool:
        """Return whether the stream has been inactive for too long."""
        return time.time() - self.last_active > idle_time

    def _append_in_order(self, payload: bytes) -> int:
        if self.data_start_seq is None:
            self.data_start_seq = self.expected_seq
        self.data.extend(payload)
        self.expected_seq += len(payload)
        return len(payload)

    def _prepend_before_start(self, seq: int, payload: bytes) -> int:
        segment_end = seq + len(payload)
        if segment_end < self.data_start_seq:
            self._buffer_out_of_order(seq, payload)
            return 0

        prepend_len = self.data_start_seq - seq
        if prepend_len <= 0:
            return 0

        self.data = bytearray(payload[:prepend_len]) + self.data
        if segment_end > self.data_start_seq:
            self.overlap_bytes += segment_end - self.data_start_seq
        self.data_start_seq = seq
        return prepend_len

    def _buffer_out_of_order(self, seq: int, payload: bytes) -> None:
        existing = self.segments.get(seq)
        if existing is not None:
            self.retransmission_count += 1
            if len(existing) >= len(payload):
                self.duplicate_bytes += len(payload)
                return
            self.duplicate_bytes += len(existing)

        self.segments[seq] = payload
        self.out_of_order_count += 1
        self.gap_count += 1

    def _flush_contiguous_segments(self) -> int:
        added = 0
        while self.segments:
            exact = self.segments.pop(self.expected_seq, None)
            if exact is not None:
                added += self._append_in_order(exact)
                continue

            overlapping_seq = None
            for seq, payload in self.segments.items():
                if seq < self.expected_seq < seq + len(payload):
                    overlapping_seq = seq
                    break

            if overlapping_seq is None:
                break

            payload = self.segments.pop(overlapping_seq)
            overlap = self.expected_seq - overlapping_seq
            self.overlap_bytes += overlap
            added += self._append_in_order(payload[overlap:])

        return added


class TCPStreamReassembler:
    """Thread-safe TCP stream reassembler with LRU cleanup."""

    def __init__(self, timeout: float = 300, max_stream_size: int = 10 * 1024 * 1024,
                 max_streams: int = 1000, idle_timeout: float = 60):
        self.timeout = timeout
        self.max_stream_size = max_stream_size
        self.max_streams = max_streams
        self.idle_timeout = idle_timeout

        self._streams: Dict[tuple, StreamBuffer] = OrderedDict()
        self._lock = threading.RLock()

        self.total_streams_created = 0
        self.total_streams_expired = 0
        self.total_bytes_reassembled = 0

        self._running = True
        self._cleaner_thread = threading.Thread(target=self._cleaner_loop, daemon=True)
        self._cleaner_thread.start()

    def feed(self, parsed: Dict[str, Any]) -> Optional[bytes]:
        """Feed one parsed TCP packet and return stream data when new bytes arrive."""
        src_ip = parsed.get("src_ip")
        dst_ip = parsed.get("dst_ip")
        src_port = parsed.get("src_port")
        dst_port = parsed.get("dst_port")
        seq = parsed.get("seq")
        payload = parsed.get("payload", b"")

        if not all([src_ip, dst_ip, src_port, dst_port]):
            return None
        if not payload:
            return None

        # TCP sequence numbers are directional. Strict reassembly therefore
        # keeps client->server and server->client payloads in separate buffers.
        from core.protocol_parser import ProtocolParser
        flow_key = ProtocolParser.get_flow_key_directional(src_ip, dst_ip, src_port, dst_port)

        with self._lock:
            if flow_key not in self._streams:
                if len(self._streams) >= self.max_streams:
                    self._evict_oldest_stream()
                stream = StreamBuffer(flow_key, src_ip, dst_ip, src_port, dst_port)
                self._streams[flow_key] = stream
                self.total_streams_created += 1

            stream = self._streams[flow_key]

            if len(stream.data) + len(payload) > self.max_stream_size:
                stream.clear_data()

            new_bytes = stream.add_segment(seq, payload)
            self.total_bytes_reassembled += new_bytes
            self._streams.move_to_end(flow_key)

            if new_bytes > 0:
                return stream.get_data()

        return None

    def get_stream(self, flow_key: tuple) -> bytes:
        """Return the data for a specific directional flow key."""
        with self._lock:
            stream = self._streams.get(flow_key)
            return stream.get_data() if stream else b""

    def get_all_streams(self) -> List[Tuple[tuple, bytes]]:
        """Return all current streams as (flow_key, data)."""
        with self._lock:
            return [(key, stream.get_data()) for key, stream in self._streams.items()]

    def get_stream_info(self, flow_key: tuple) -> Optional[Dict[str, Any]]:
        """Return detailed metadata for one stream."""
        with self._lock:
            stream = self._streams.get(flow_key)
            if stream is None:
                return None
            return {
                "src_ip": stream.src_ip,
                "dst_ip": stream.dst_ip,
                "src_port": stream.src_port,
                "dst_port": stream.dst_port,
                "data_size": len(stream.data),
                "buffered_segments": len(stream.segments),
                "data_start_seq": stream.data_start_seq,
                "expected_seq": stream.expected_seq,
                "total_bytes": stream.total_bytes,
                "packets": stream.packet_count,
                "out_of_order_segments": stream.out_of_order_count,
                "retransmissions": stream.retransmission_count,
                "duplicate_bytes": stream.duplicate_bytes,
                "overlap_bytes": stream.overlap_bytes,
                "gaps_seen": stream.gap_count,
                "start_time": stream.start_time,
                "last_active": stream.last_active,
            }

    def clear_stream(self, flow_key: tuple) -> bool:
        """Delete one stream."""
        with self._lock:
            if flow_key in self._streams:
                del self._streams[flow_key]
                return True
        return False

    def get_stats(self) -> Dict[str, Any]:
        """Return aggregate reassembly statistics."""
        with self._lock:
            return {
                "active_streams": len(self._streams),
                "total_streams_created": self.total_streams_created,
                "total_streams_expired": self.total_streams_expired,
                "total_bytes_reassembled": self.total_bytes_reassembled,
                "total_data_buffered": sum(len(s.data) for s in self._streams.values()),
                "buffered_segments": sum(len(s.segments) for s in self._streams.values()),
                "out_of_order_segments": sum(s.out_of_order_count for s in self._streams.values()),
                "retransmissions": sum(s.retransmission_count for s in self._streams.values()),
            }

    def shutdown(self) -> None:
        """Stop the background cleanup thread."""
        self._running = False
        self._cleaner_thread.join(timeout=5)

    def _evict_oldest_stream(self) -> None:
        if self._streams:
            oldest_key = next(iter(self._streams))
            del self._streams[oldest_key]
            self.total_streams_expired += 1

    def _cleaner_loop(self) -> None:
        while self._running:
            time.sleep(30)
            self._cleanup()

    def _cleanup(self) -> None:
        with self._lock:
            expired_keys = []
            for key, stream in self._streams.items():
                if stream.is_expired(self.timeout):
                    expired_keys.append(key)
                elif stream.is_idle(self.idle_timeout) and len(stream.data) < 1024:
                    expired_keys.append(key)

            for key in expired_keys:
                del self._streams[key]
                self.total_streams_expired += 1
