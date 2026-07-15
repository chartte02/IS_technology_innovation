# ============================================================
# 核心引擎模块
# ============================================================

from core.packet_capture import PacketCapture
from core.protocol_parser import ProtocolParser, AppProtocol
try:
    from core.tls_detector import TLSDetector, TLSParseError
except ImportError:
    TLSDetector = None   # type: ignore
    TLSParseError = None # type: ignore
from core.tcp_reassembler import TCPStreamReassembler, StreamBuffer
from core.misuse_detector import SignatureMatcher, Signature
from core.anomaly_detector import AnomalyDetector, HostStats, BaselineProfile
from core.alert_manager import AlertManager, Alert
from core.baseline_learner import BaselineLearner

__all__ = [
    'PacketCapture',
    'ProtocolParser',
    'AppProtocol',
    'TLSDetector',
    'TLSParseError',
    'TCPStreamReassembler',
    'StreamBuffer',
    'SignatureMatcher',
    'Signature',
    'AnomalyDetector',
    'HostStats',
    'BaselineProfile',
    'AlertManager',
    'Alert',
    'BaselineLearner',
]
