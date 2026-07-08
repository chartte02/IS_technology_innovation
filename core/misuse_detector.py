# ============================================================
# 模块: 误用检测引擎 (misuse_detector.py)
# 功能: 基于攻击特征库进行多模式匹配，检测已知攻击
# 负责人: 成员A (核心模块)
# ============================================================

import re
import os
import time
import yaml
import logging
from typing import List, Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)


# ─── 攻击特征数据结构 ───

class Signature:
    """单条攻击特征"""

    __slots__ = ('sig_id', 'name', 'category', 'severity',
                 'patterns', 'threshold', 'protocols', 'ports',
                 'enabled')

    def __init__(self, raw: Dict[str, Any]):
        self.sig_id = raw.get('id', 'UNKNOWN')
        self.name = raw.get('name', 'Unknown Signature')
        self.category = raw.get('category', 'unknown')
        self.severity = raw.get('severity', 'medium')  # critical/high/medium/low
        self.patterns = raw.get('patterns', [])
        self.threshold = raw.get('threshold', None)
        self.protocols = raw.get('protocols', None)  # 限定的协议列表
        self.ports = raw.get('ports', None)           # 限定的端口列表
        self.enabled = raw.get('enabled', True)

    def to_dict(self) -> Dict:
        return {
            'id': self.sig_id,
            'name': self.name,
            'category': self.category,
            'severity': self.severity,
        }


class SignatureMatcher:
    """
    误用检测引擎 — 基于特征串匹配

    实现策略:
    1. 字符串特征 → Aho-Corasick 自动机（O(n) 高效匹配）
    2. 正则特征   → 预编译 re.compile，分组批量匹配
    3. 按协议/端口分类索引，减少无用匹配
    4. 支持阈值型规则（暴力破解等需要状态追踪）

    使用示例:
        matcher = SignatureMatcher('./signatures')
        matcher.load_all()
        alerts = matcher.match_packet(parsed_packet)
    """

    def __init__(self, sig_dir: str = './signatures'):
        self.sig_dir = sig_dir
        self.all_signatures: List[Signature] = []
        self.total_loaded = 0

        # AC 自动机（字符串特征）
        self._ac_automaton = None
        self._ac_sig_map: Dict[int, Signature] = {}  # ac_index → signature

        # 正则特征
        self._regex_matchers: List[Tuple[re.Pattern, Signature]] = []

        # 按端口的快速索引: port → [(pattern, signature)]
        self._port_index: Dict[int, List] = {}

        # 按协议的快速索引: protocol → [(pattern, signature)]
        self._proto_index: Dict[str, List] = {}

        # 阈值型规则的状态追踪: sig_id → {key: [timestamps]}
        self._threshold_states: Dict[str, Dict[str, List[float]]] = {}

    # ─── 特征库加载 ───

    def load_all(self) -> int:
        """加载所有特征库文件"""
        yaml_files = [f for f in os.listdir(self.sig_dir) if f.endswith('.yaml')]
        total = 0
        for fname in sorted(yaml_files):
            filepath = os.path.join(self.sig_dir, fname)
            count = self._load_file(filepath)
            total += count
            logger.info(f"特征库加载: {fname} → {count} 条规则")

        self.total_loaded = total
        self._build_indices()
        logger.info(f"特征库加载完成: 共 {total} 条规则")
        logger.info(f"  AC 自动机: {len(self._ac_sig_map)} 个模式")
        logger.info(f"  正则匹配器: {len(self._regex_matchers)} 个模式")
        return total

    def _load_file(self, filepath: str) -> int:
        """加载单个 YAML 特征文件"""
        with open(filepath, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        if not isinstance(data, list):
            logger.warning(f"跳过无效特征文件: {filepath}（非列表格式）")
            return 0

        count = 0
        for item in data:
            if not isinstance(item, dict):
                continue
            try:
                sig = Signature(item)
                self.all_signatures.append(sig)
                count += 1
            except Exception as e:
                logger.error(f"解析特征失败: {item.get('id', '?')} - {e}")

        return count

    def _build_indices(self):
        """构建所有匹配索引"""
        # 清理
        self._ac_sig_map.clear()
        self._regex_matchers.clear()
        self._port_index.clear()
        self._proto_index.clear()

        for sig in self.all_signatures:
            if not sig.enabled:
                continue

            for p_idx, pattern in enumerate(sig.patterns):
                # 判断是纯字符串还是正则
                is_regex, compiled = self._classify_pattern(pattern)
                match_key = (sig, p_idx)

                if is_regex:
                    self._regex_matchers.append((compiled, sig))
                else:
                    # 存入 AC 自动机
                    if self._ac_automaton is None:
                        try:
                            import ahocorasick
                            self._ac_automaton = ahocorasick.Automaton()
                        except ImportError:
                            logger.warning("pyahocorasick 未安装，字符串匹配将退化为遍历匹配")
                            # 退化为简单匹配器
                            self._ac_automaton = None

                    if self._ac_automaton is not None:
                        # AC automaton uses lowercase for case-insensitive matching
                        ac_pattern = pattern.lower()
                        key = (sig.category, sig.sig_id, p_idx)
                        self._ac_automaton.add_word(ac_pattern, key)
                        self._ac_sig_map[key] = sig

                self._add_to_port_index(sig, compiled)
                self._add_to_proto_index(sig, compiled)

        # 最终化 AC 自动机
        if self._ac_automaton is not None:
            try:
                self._ac_automaton.make_automaton()
            except Exception as e:
                logger.error(f"AC 自动机构建失败: {e}")
                self._ac_automaton = None

    def _classify_pattern(self, pattern: str) -> Tuple[bool, Any]:
        """
        判断模式是纯字符串还是正则表达式

        Returns:
            (is_regex: bool, compiled: re.Pattern | str)
        """
        # 检查正则元字符
        regex_chars = ['.*', '.+', '[', ']', '(', ')', '\\d', '\\w', '\\s',
                       '(?i)', '(?m)', '(?s)', '^', '$', '{']
        is_regex = any(rc in pattern for rc in regex_chars)

        if is_regex:
            # 处理内联标志
            try:
                compiled = re.compile(
                    pattern,
                    re.IGNORECASE if '(?i)' in pattern else 0
                )
            except re.error:
                # 正则编译失败（如括号未闭合），降级为纯字符串匹配
                logger.warning(
                    f"Invalid regex pattern, falling back to literal: {pattern[:60]}"
                )
                is_regex = False
                compiled = pattern.lower()
        else:
            # 纯字符串，转小写用于大小写不敏感匹配
            compiled = pattern.lower()

        return is_regex, compiled

    def _add_to_port_index(self, sig: Signature, compiled: Any):
        """添加到端口索引"""
        if sig.ports:
            ports = sig.ports if isinstance(sig.ports, list) else [sig.ports]
            for port in ports:
                if port not in self._port_index:
                    self._port_index[port] = []
                self._port_index[port].append((compiled, sig))

    def _add_to_proto_index(self, sig: Signature, compiled: Any):
        """添加到协议索引"""
        if sig.protocols:
            protos = sig.protocols if isinstance(sig.protocols, list) else [sig.protocols]
            for proto in protos:
                proto_lower = proto.lower()
                if proto_lower not in self._proto_index:
                    self._proto_index[proto_lower] = []
                self._proto_index[proto_lower].append((compiled, sig))

    # ─── 核心匹配方法 ───

    def match_packet(self, parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        对单个已解析的数据包进行特征匹配

        Args:
            parsed: ProtocolParser.parse() 返回的包信息

        Returns:
            list: 匹配到的告警列表，每个元素为:
                {
                    'signature_id': str,
                    'signature_name': str,
                    'category': str,
                    'severity': str,
                    'matched_pattern': str,
                    'matched_position': int,
                    'src_ip': str,
                    'dst_ip': str,
                    'dst_port': int,
                    'app_protocol': str,
                    'timestamp': float,
                }
        """
        payload = parsed.get('payload', b'')
        if not payload:
            return []

        alerts = []
        dst_port = parsed.get('dst_port', 0)
        proto = parsed.get('app_protocol')
        proto_str = proto.value if proto and hasattr(proto, 'value') else 'unknown'

        # 准备匹配素材
        payload_str = payload.decode('utf-8', errors='ignore')
        payload_lower = payload_str.lower()

        # Stage 1: AC 自动机匹配（字符串特征）
        ac_alerts = self._match_ac(payload_lower, parsed)
        alerts.extend(ac_alerts)

        # Stage 2: 正则表达式匹配
        # 按协议/端口筛选，减少不必要的正则匹配
        regex_candidates = self._get_regex_candidates(dst_port, proto_str)
        regex_alerts = self._match_regex(payload_str, payload_lower,
                                          regex_candidates, parsed)
        alerts.extend(regex_alerts)

        # Stage 3: 阈值型规则检查
        threshold_alerts = self._check_threshold_rules(parsed)
        alerts.extend(threshold_alerts)

        # 去重（同一条规则在一个包中只保留一条告警）
        alerts = self._deduplicate_alerts(alerts)

        return alerts

    def match_stream(self, stream_data: bytes, flow_info: Dict) -> List[Dict]:
        """
        对 TCP 流重组后的完整数据进行匹配

        Args:
            stream_data: 流重组后的完整数据
            flow_info: 流的元信息（IP/端口等）
        """
        # 构造虚拟的 parsed 对象
        parsed = {
            'src_ip': flow_info.get('src_ip', ''),
            'dst_ip': flow_info.get('dst_ip', ''),
            'src_port': flow_info.get('src_port', 0),
            'dst_port': flow_info.get('dst_port', 0),
            'payload': stream_data,
            'timestamp': time.time(),
            'app_protocol': 'STREAM',
        }
        return self.match_packet(parsed)

    # ─── 匹配子方法 ───

    def _match_ac(self, payload_lower: str, parsed: Dict) -> List[Dict]:
        """AC 自动机匹配"""
        alerts = []
        if self._ac_automaton is None:
            return alerts

        seen_sig_ids = set()
        for end_idx, (category, sig_id, p_idx) in self._ac_automaton.iter(payload_lower):
            if sig_id in seen_sig_ids:
                continue
            seen_sig_ids.add(sig_id)

            # 查找对应的 signature
            sig = self._ac_sig_map.get((category, sig_id, p_idx))
            if sig is None:
                continue

            # 确认匹配位置
            pattern = sig.patterns[p_idx]
            matched_text = payload_lower[max(0, end_idx - len(pattern)):end_idx + 1]

            alerts.append(self._build_alert(sig, pattern, matched_text, parsed))

        return alerts

    def _match_regex(self, payload_str: str, payload_lower: str,
                      candidates: List[Tuple], parsed: Dict) -> List[Dict]:
        """正则表达式匹配"""
        alerts = []
        seen_sig_ids = set()

        for compiled, sig in candidates:
            if sig.sig_id in seen_sig_ids:
                continue

            if isinstance(compiled, str):
                # 纯字符串 fallback
                if compiled in payload_lower:
                    alerts.append(self._build_alert(sig, compiled, compiled, parsed))
                    seen_sig_ids.add(sig.sig_id)
            else:
                # 正则
                match = compiled.search(payload_str)
                if match:
                    alerts.append(self._build_alert(sig, compiled.pattern,
                                                     match.group(), parsed))
                    seen_sig_ids.add(sig.sig_id)

        return alerts

    def _get_regex_candidates(self, port: int, proto: str) -> List[Tuple]:
        """获取候选正则匹配器（按端口和协议筛选）"""
        candidates = []

        # 端口匹配
        if port in self._port_index:
            candidates.extend(self._port_index[port])

        # 协议匹配
        if proto in self._proto_index:
            candidates.extend(self._proto_index[proto])

        # 如果没有索引命中，使用所有正则
        if not candidates:
            candidates = self._regex_matchers

        return candidates

    def _check_threshold_rules(self, parsed: Dict) -> List[Dict]:
        """检查阈值型规则（如暴力破解）"""
        alerts = []
        src_ip = parsed.get('src_ip', '')
        dst_ip = parsed.get('dst_ip', '')
        port = parsed.get('dst_port', 0)
        now = time.time()

        # 查找当前包的阈值规则
        for sig in self.all_signatures:
            if not sig.threshold:
                continue
            if not any(self._match_fingerprint(p, parsed, sig) for p in sig.patterns):
                continue

            # 该包的 pattern 命中了阈值规则的触发条件
            sig_key = sig.sig_id
            flow_key = f"{src_ip}→{dst_ip}:{port}"

            if sig_key not in self._threshold_states:
                self._threshold_states[sig_key] = {}

            state = self._threshold_states[sig_key]
            if flow_key not in state:
                state[flow_key] = []

            # 清理过期记录
            window = sig.threshold.get('window', 60)
            state[flow_key] = [t for t in state[flow_key] if now - t < window]
            state[flow_key].append(now)

            # 检查是否超过阈值
            threshold_count = sig.threshold.get('count', 5)
            if len(state[flow_key]) >= threshold_count:
                alerts.append({
                    'signature_id': sig.sig_id,
                    'signature_name': sig.name,
                    'category': sig.category,
                    'severity': sig.severity,
                    'matched_pattern': f"threshold: {len(state[flow_key])}/{threshold_count} in {window}s",
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'dst_port': port,
                    'timestamp': now,
                })
                # 重置计数防止重复告警
                state[flow_key] = []

        return alerts

    def _match_fingerprint(self, pattern: str, parsed: Dict, sig: Signature) -> bool:
        """检查单个包的载荷是否匹配某 pattern 的一部分（用于触发阈值追踪）"""
        payload = parsed.get('payload', b'')
        if not payload:
            return False
        try:
            payload_str = payload.decode('utf-8', errors='ignore').lower()
            return pattern.lower() in payload_str
        except Exception:
            return False

    # ─── 告警构造 ───

    def _build_alert(self, sig: Signature, pattern: str,
                     matched_text: str, parsed: Dict) -> Dict:
        """构造告警字典"""
        return {
            'signature_id': sig.sig_id,
            'signature_name': sig.name,
            'category': sig.category,
            'severity': sig.severity,
            'matched_pattern': pattern,
            'matched_text': matched_text[:100],  # 截断显示
            'src_ip': parsed.get('src_ip', ''),
            'dst_ip': parsed.get('dst_ip', ''),
            'src_port': parsed.get('src_port', 0),
            'dst_port': parsed.get('dst_port', 0),
            'timestamp': parsed.get('timestamp', time.time()),
        }

    @staticmethod
    def _deduplicate_alerts(alerts: List[Dict]) -> List[Dict]:
        """合并同一规则对同一来源的重复告警"""
        seen = set()
        unique = []
        for alert in alerts:
            key = (alert['signature_id'], alert['src_ip'], alert['dst_ip'])
            if key not in seen:
                seen.add(key)
                unique.append(alert)
        return unique

    # ─── 特征库管理 ───

    def reload(self) -> int:
        """重新加载所有特征库（热更新）"""
        self.all_signatures.clear()
        self._ac_sig_map.clear()
        self._regex_matchers.clear()
        self._port_index.clear()
        self._proto_index.clear()
        self._threshold_states.clear()
        return self.load_all()

    def get_signature_by_id(self, sig_id: str) -> Optional[Signature]:
        """按 ID 查找特征"""
        for sig in self.all_signatures:
            if sig.sig_id == sig_id:
                return sig
        return None

    def get_signatures_by_category(self, category: str) -> List[Signature]:
        """按类别获取特征"""
        return [s for s in self.all_signatures if s.category == category]

    def get_statistics(self) -> Dict[str, Any]:
        """获取特征库统计"""
        cats = {}
        for s in self.all_signatures:
            cats[s.category] = cats.get(s.category, 0) + 1
        return {
            'total_signatures': len(self.all_signatures),
            'by_category': cats,
            'ac_patterns': len(self._ac_sig_map),
            'regex_patterns': len(self._regex_matchers),
        }


# ─── 简单模式匹配器（pyahocorasick 不可用时的 fallback） ───

class SimpleMultiPatternMatcher:
    """基于 Python 内置 str.find 的简单多模式匹配器"""

    def __init__(self):
        self.patterns: Dict[str, Any] = {}

    def add_pattern(self, pattern: str, value: Any):
        self.patterns[pattern] = value

    def search_all(self, text: str) -> List[Tuple[int, Any]]:
        """返回 [(position, value), ...]"""
        results = []
        text_lower = text.lower()
        for pattern, value in self.patterns.items():
            pos = text_lower.find(pattern.lower())
            if pos >= 0:
                results.append((pos, value))
        results.sort()
        return results
