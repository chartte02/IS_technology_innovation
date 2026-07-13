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
from collections import defaultdict
from typing import List, Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)


# ─── 攻击特征数据结构 ───

class Signature:
    """单条攻击特征"""

    __slots__ = ('sig_id', 'name', 'category', 'severity',
                 'patterns', 'threshold', 'protocols', 'ports',
                 'flowbits', 'enabled')

    def __init__(self, raw: Dict[str, Any]):
        self.sig_id = raw.get('id', 'UNKNOWN')
        self.name = raw.get('name', 'Unknown Signature')
        self.category = raw.get('category', 'unknown')
        self.severity = raw.get('severity', 'medium')
        self.patterns = raw.get('patterns', [])
        self.threshold = raw.get('threshold', None)
        self.protocols = raw.get('protocols', None)
        self.ports = raw.get('ports', None)
        self.enabled = raw.get('enabled', True)
        # Flowbits: 跨规则状态传递 (Suricata 兼容)
        fb = raw.get('flowbits', {}) or {}
        self.flowbits = {
            'set':     fb.get('set', []),       # 命中后设置的 flag
            'require': fb.get('require', []),   # 需要前置规则已设置这些 flag
            'track':   fb.get('track', 'by_src'),  # 追踪粒度: by_src/by_dst/both
        }

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

        # Flowbits 状态: flow_key → set(flag_names)  (跨规则状态传递)
        self._flowbits_state: Dict[str, set] = defaultdict(set)

        # 白名单 IP（来自这些 IP 的告警直接忽略）
        self._whitelist_ips: set = set()

        # 内网 IP 前缀（来自内网的告警可能升级严重度）
        self._internal_prefixes: List[str] = []

    def set_whitelist(self, ips: List[str]) -> None:
        """设置白名单 IP 列表（如已知扫描器、安全设备等）"""
        self._whitelist_ips = set(ips)
        logger.info(f"白名单已更新: {len(self._whitelist_ips)} 个 IP")

    def set_internal_ranges(self, prefixes: List[str]) -> None:
        """设置内网 IP 前缀列表（如 ['192.168.', '10.'] ）"""
        self._internal_prefixes = prefixes

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

        # 上下文过滤：HTTP 请求的 Web 攻击特征仅检测查询参数部分
        # 避免路径中包含 "select" "/etc/" 等正常词汇触发误报
        web_payload_str, web_payload_lower = self._extract_web_context(
            parsed, payload_str, payload_lower)

        # Stage 1: AC 自动机匹配（字符串特征）— 全文匹配
        web_categories = {'sql_injection', 'xss', 'web_attack', 'webshell'}
        ac_alerts = self._match_ac(payload_lower, parsed)
        # AC 自动机告警也需要上下文过滤
        ac_alerts = self._filter_web_false_positives(
            ac_alerts, parsed, web_categories)
        alerts.extend(ac_alerts)

        # Stage 2: 正则表达式匹配
        # Web 类攻击仅检测查询参数（降低误报），非 Web 类检测全文
        regex_candidates = self._get_regex_candidates(dst_port, proto_str)
        regex_alerts = self._match_regex(payload_str, payload_lower,
                                          regex_candidates, parsed)
        # 对 Web 类告警做上下文二次确认
        regex_alerts = self._filter_web_false_positives(
            regex_alerts, parsed, web_categories)
        alerts.extend(regex_alerts)

        # Stage 3: 阈值型规则检查
        threshold_alerts = self._check_threshold_rules(parsed)
        alerts.extend(threshold_alerts)

        # Stage 4: Flowbits 跨规则状态传递 (Suricata 兼容)
        alerts = self._apply_flowbits(alerts, parsed)

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

    # ─── 上下文过滤（降低误报率）───

    @staticmethod
    def _extract_web_context(parsed: Dict, payload_str: str,
                              payload_lower: str) -> tuple:
        """
        从 HTTP 请求中提取 Web 攻击检测的上下文。
        仅提取 URI 查询参数部分（? 之后），避免路径中的正常词汇触发误报。

        例如:
          /select-course?id=1 UNION SELECT  → 提取 "id=1 UNION SELECT"
          /etc/passwd                        → 提取 "/etc/passwd" (无 ? 则全量)
          SSH 流量                            → 保持全量

        Returns:
            (web_payload_str, web_payload_lower)
        """
        http_uri = parsed.get('http_uri')
        if http_uri and '?' in http_uri:
            # 提取查询参数部分
            query_part = http_uri.split('?', 1)[1]
            return query_part, query_part.lower()
        # 非 HTTP 或无查询参数，使用全量
        return payload_str, payload_lower

    def _filter_web_false_positives(self, alerts: List[Dict],
                                     parsed: Dict,
                                     web_categories: set) -> List[Dict]:
        """
        对 Web 类告警做上下文感知二次确认。

        过滤策略（多层降噪）:
        1. 白名单 IP: 来自白名单 IP 的告警直接忽略
        2. URL 路径匹配: 仅在路径不在查询参数中 → 降为 low
        3. Referer 匹配: 仅在 Referer 头中 → 降为 low（可能是外部诱饵链接）
        4. Cookie 匹配: 仅在 Cookie 中 → 降为 low（可能是正常 token）

        Returns:
            过滤后的告警列表
        """
        if not alerts:
            return alerts

        src_ip = parsed.get('src_ip', '')

        # 提取 HTTP 头信息
        headers = self._extract_http_headers(parsed)
        referer = headers.get('referer', '').lower()
        cookie = headers.get('cookie', '').lower()

        http_uri = parsed.get('http_uri', '')
        query_part = ''
        path_part = http_uri.lower()
        has_query = '?' in http_uri
        if has_query:
            query_part = http_uri.split('?', 1)[1].lower()
            path_part = http_uri.split('?', 1)[0].lower()

        filtered = []
        for alert in alerts:
            cat = alert.get('category', '')

            # 非 Web 类告警不参与上下文过滤
            if cat not in web_categories:
                filtered.append(alert)
                continue

            # ── 1. 白名单 IP 直接跳过 ──
            if src_ip in self._whitelist_ips:
                logger.debug(
                    f"白名单 IP {src_ip} 的告警已忽略: "
                    f"{alert.get('signature_id', '?')}"
                )
                continue

            alert = dict(alert)
            matched = alert.get('matched_text', '').lower()
            downgraded = False

            # ── 2. 仅 URL 路径匹配 → 降级 ──
            if (matched and has_query
                    and matched not in query_part
                    and matched in path_part):
                alert['severity'] = 'low'
                alert['description'] = (
                    f"[低可信度] {alert.get('description', '')} "
                    f"(匹配位于URL路径: {path_part[:50]})"
                )
                downgraded = True

            # ── 3. 仅 Referer 头匹配 → 降级 ──
            if (matched and referer and matched in referer
                    and not (query_part and matched in query_part)):
                alert['severity'] = 'low'
                alert['description'] = (
                    f"[低可信度-Referer] {alert.get('description', '')} "
                    f"(匹配位于Referer头而非请求参数)"
                )
                downgraded = True

            # ── 4. 仅 Cookie 匹配 → 降级 ──
            if (matched and cookie and matched in cookie
                    and not (query_part and matched in query_part)
                    and not (referer and matched in referer)):
                alert['severity'] = 'low'
                alert['description'] = (
                    f"[低可信度-Cookie] {alert.get('description', '')} "
                    f"(匹配位于Cookie而非请求参数)"
                )
                downgraded = True

            filtered.append(alert)

        return filtered

    @staticmethod
    def _extract_http_headers(parsed: Dict) -> Dict[str, str]:
        """
        从 HTTP 载荷中提取关键头部字段。

        Returns:
            dict with keys: 'referer', 'cookie', 'user_agent'
        """
        headers = {}
        payload = parsed.get('payload', b'')
        if not payload:
            return headers

        try:
            text = payload.decode('utf-8', errors='ignore')
            # 提取 HTTP 头部区域（\r\n\r\n 之前）
            header_end = text.find('\r\n\r\n')
            if header_end < 0:
                header_end = text.find('\n\n')
            header_section = text[:header_end] if header_end > 0 else text

            for line in header_section.split('\r\n'):
                if ':' not in line:
                    continue
                key, _, value = line.partition(':')
                key_lower = key.strip().lower()
                if key_lower in ('referer', 'cookie', 'user-agent'):
                    headers[key_lower.replace('-', '_')] = value.strip()
        except Exception:
            pass

        return headers

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
        """获取候选正则匹配器（按端口和协议筛选 + 无限制规则全量）"""
        candidates = list(self._regex_matchers)  # 包含所有无端口/协议限制的规则

        # 端口匹配 — 额外加入端口专属规则
        if port in self._port_index:
            candidates.extend(self._port_index[port])

        # 协议匹配
        if proto in self._proto_index:
            candidates.extend(self._proto_index[proto])

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
                    'type': sig.category,
                    'category': sig.category,
                    'severity': sig.severity,
                    'description': (
                        f"检测到 {sig.name}，"
                        f"在 {window}s 内触发 {len(state[flow_key])}/{threshold_count} 次，"
                        f"来源: {src_ip} → {dst_ip}:{port}"
                    ),
                    'matched_pattern': (
                        f"threshold: {len(state[flow_key])}/{threshold_count}"
                        f" in {window}s"
                    ),
                    'matched_text': '',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': parsed.get('src_port', 0),
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

    # ─── Flowbits 跨规则状态传递 (Suricata 兼容) ───

    def _apply_flowbits(self, alerts: List[Dict], parsed: Dict) -> List[Dict]:
        """
        Stage 4: 跨规则状态传递。

        流程:
        1. 检查告警规则的 flowbits.require → 不满足则丢弃
        2. 保留的告警，设置其 flowbits.set 标记

        flow key 由 track 策略决定:
          by_src → "{src_ip}"
          by_dst → "{dst_ip}"
          both   → "{src_ip}→{dst_ip}"
        """
        src_ip = parsed.get('src_ip', '')
        dst_ip = parsed.get('dst_ip', '')
        filtered = []
        flags_to_set = []

        for alert in alerts:
            sig_id = alert.get('signature_id', '')
            sig = self.get_signature_by_id(sig_id)
            if sig is None:
                filtered.append(alert)
                continue

            fb = sig.flowbits
            require = fb.get('require', [])
            set_flags = fb.get('set', [])
            track = fb.get('track', 'by_src')
            flow_key = self._get_flowbit_key(src_ip, dst_ip, track)

            # 检查前置条件
            active = self._flowbits_state.get(flow_key, set())
            missing = [f for f in require if f not in active]
            if missing:
                logger.debug(f"Flowbits: {sig_id} 跳过, 缺少 {missing}")
                continue

            filtered.append(alert)
            if set_flags:
                flags_to_set.append((flow_key, set_flags))

        # 统一设置 flags
        for flow_key, flags in flags_to_set:
            if flow_key not in self._flowbits_state:
                self._flowbits_state[flow_key] = set()
            self._flowbits_state[flow_key].update(flags)

        return filtered

    @staticmethod
    def _get_flowbit_key(src_ip: str, dst_ip: str, track: str) -> str:
        if track == 'by_dst':
            return dst_ip
        elif track == 'both':
            return f"{src_ip}->{dst_ip}"
        return src_ip  # by_src

    # ─── 告警构造 ───

    # MITRE ATT&CK 映射: category → (tactic_id, tactic_name, technique_id, technique_name)
    MITRE_ATTACK_MAP = {
        'sql_injection':  ('TA0001', 'Initial Access', 'T1190', 'Exploit Public-Facing Application'),
        'xss':            ('TA0001', 'Initial Access', 'T1189', 'Drive-by Compromise'),
        'web_attack':     ('TA0001', 'Initial Access', 'T1190', 'Exploit Public-Facing Application'),
        'webshell':       ('TA0003', 'Persistence',     'T1505', 'Server Software Component'),
        'brute_force':    ('TA0006', 'Credential Access','T1110', 'Brute Force'),
        'backdoor':       ('TA0011', 'Command & Control','T1071', 'Application Layer Protocol'),
        'dos':            ('TA0040', 'Impact',           'T1498', 'Network Denial of Service'),
        'scan':           ('TA0043', 'Reconnaissance',   'T1046', 'Network Service Discovery'),
    }

    def _build_alert(self, sig: Signature, pattern: str,
                     matched_text: str, parsed: Dict) -> Dict:
        """构造告警字典，对齐接口约定 (CLAUDE.md §5.2)，含 MITRE ATT&CK 映射"""
        mitre = self.MITRE_ATTACK_MAP.get(sig.category, ('', '', '', ''))
        return {
            'signature_id': sig.sig_id,
            'signature_name': sig.name,
            'type': sig.category,
            'category': sig.category,
            'severity': sig.severity,
            'description': (
                f"检测到 {sig.name}，"
                f"匹配模式: {pattern[:80]}，"
                f"来源: {parsed.get('src_ip', '?')}:{parsed.get('src_port', '?')}"
            ),
            'matched_pattern': pattern,
            'matched_text': matched_text[:100],
            'src_ip': parsed.get('src_ip', ''),
            'dst_ip': parsed.get('dst_ip', ''),
            'src_port': parsed.get('src_port', 0),
            'dst_port': parsed.get('dst_port', 0),
            'timestamp': parsed.get('timestamp', time.time()),
            # MITRE ATT&CK 扩展字段
            'mitre_tactic':       f"{mitre[0]} - {mitre[1]}",
            'mitre_technique':    f"{mitre[2]} - {mitre[3]}",
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
