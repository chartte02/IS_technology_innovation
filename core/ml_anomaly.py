# ============================================================
# 模块: ML 异常检测引擎 (ml_anomaly.py)
# 功能: 基于 Isolation Forest 的无监督机器学习异常检测
# 负责人: 成员C
# ============================================================
# 使用示例:
#   ml = MLAnomalyDetector()
#   ml.collect_features(host_stats)  # 收集特征
#   ml.train()                        # 训练模型
#   result = ml.predict(host_stats)   # -1=异常, 1=正常
# ============================================================

import time
import logging
import threading
from typing import Dict, List, Optional, Tuple, Any

import numpy as np

logger = logging.getLogger(__name__)

try:
    from sklearn.ensemble import IsolationForest
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    logger.warning("scikit-learn 未安装，ML异常检测不可用。pip install scikit-learn")


class MLAnomalyDetector:
    """
    基于 Isolation Forest 的无监督异常检测器

    特征向量（8维，每台主机一个向量）:
    [0] conn_count:       连接数
    [1] syn_count:        SYN 包数
    [2] unique_ports:     不同目标端口数
    [3] unique_ips:       不同目标 IP 数
    [4] bytes_sent:       发出字节数
    [5] bytes_received:   接收字节数
    [6] packet_rate:      包速率 (packet_count / duration)
    [7] login_failures:   登录失败次数

    训练方式:
    - 在学习模式下收集正常流量的特征向量
    - 累积到 min_samples 后自动训练模型
    - 训练完成后对每台主机实时预测

    与固定阈值对比:
    - 固定阈值: 硬编码阈值，需手动调参，不同网络环境需重新调整
    - Isolation Forest: 自适应数据分布，无需手动设置阈值
    """

    def __init__(self, config: Optional[Dict] = None):
        cfg = config or {}

        # Isolation Forest 参数
        self.n_estimators = cfg.get('n_estimators', 100)
        self.contamination = cfg.get('contamination', 0.05)
        self.max_samples = cfg.get('max_samples', 'auto')
        self.random_state = cfg.get('random_state', 42)

        # 训练控制
        self.min_samples = cfg.get('min_samples', 20)       # 最少样本数
        self.max_features = cfg.get('max_features', 8)      # 特征维度

        # 状态
        self.model: Optional[IsolationForest] = None
        self._feature_cache: Dict[str, np.ndarray] = {}     # IP → 当前特征向量
        self._training_data: List[np.ndarray] = []           # 训练样本列表
        self._valid_cols: Optional[np.ndarray] = None         # 训练时有效特征列掩码
        self._trained = False
        self._training = False
        self._lock = threading.RLock()

        # 统计
        self.total_predictions = 0
        self.total_anomalies = 0

        # 特征名（供对比分析使用）
        self.feature_names = [
            'conn_count', 'syn_count', 'unique_ports', 'unique_ips',
            'bytes_sent', 'bytes_received', 'packet_rate', 'login_failures',
        ]

    # ─── 特征提取 ───

    def extract_features(self, host_stats) -> np.ndarray:
        """
        从 HostStats 对象提取 8 维特征向量

        Args:
            host_stats: HostStats 实例（来自 anomaly_detector.py）

        Returns:
            长度为 8 的 numpy 数组
        """
        duration = max(time.time() - getattr(host_stats, 'first_seen', time.time()), 1.0)

        features = np.array([
            float(getattr(host_stats, 'conn_count', 0)),
            float(getattr(host_stats, 'syn_count', 0)),
            float(len(getattr(host_stats, 'unique_dst_ports', set()))),
            float(len(getattr(host_stats, 'unique_dst_ips', set()))),
            float(getattr(host_stats, 'bytes_sent', 0)),
            float(getattr(host_stats, 'bytes_received', 0)),
            float(getattr(host_stats, 'packet_count', 0)) / duration,
            float(getattr(host_stats, 'login_failures', 0)),
        ], dtype=np.float64)

        return features

    def _filter_features(self, vec: np.ndarray) -> np.ndarray:
        """
        根据训练时保存的有效特征列掩码过滤特征向量。
        若掩码为 None（训练时用了抖动），返回原始向量。
        """
        if self._valid_cols is not None:
            return vec[self._valid_cols]
        return vec

    def collect_features(self, host_stats) -> Optional[int]:
        """
        将单台主机的统计加入训练缓存。

        当缓存达到 min_samples 时自动触发训练。

        Args:
            host_stats: HostStats 实例

        Returns:
            -1=异常, 1=正常, None=模型未训练/未收集
        """
        if not HAS_SKLEARN:
            return 1

        features = self.extract_features(host_stats)
        ip = getattr(host_stats, 'ip', 'unknown')

        with self._lock:
            self._feature_cache[ip] = features
            self._training_data.append(features)

            # 自动训练
            if len(self._training_data) >= self.min_samples and not self._trained:
                self._train_model()

        return self.predict(host_stats=host_stats, use_cache=True)

    # ─── 模型训练 ───

    def start_training(self):
        """开始训练模式标记"""
        self._training = True
        self._training_data.clear()
        logger.info("ML 异常检测: 开始收集训练数据...")

    def train(self) -> bool:
        """
        用已收集的特征训练 Isolation Forest 模型。

        Returns:
            训练是否成功
        """
        if not HAS_SKLEARN:
            logger.error("scikit-learn 未安装，无法训练 ML 模型")
            return False

        with self._lock:
            return self._train_model()

    def _train_model(self) -> bool:
        """内部训练（持有锁时调用）"""
        if len(self._training_data) < max(self.min_samples, 5):
            logger.warning(f"ML 训练数据不足: {len(self._training_data)} < {self.min_samples}")
            return False

        X = np.array(self._training_data)

        # 检查方差（全零或常数特征会导致训练失败）
        stds = np.std(X, axis=0)
        valid_cols = stds > 1e-10
        if not np.any(valid_cols):
            # 所有特征都无方差 → 加入微小随机抖动避免训练崩溃
            noise = np.random.RandomState(42).normal(0, 1e-6, X.shape)
            X_filtered = X + noise
            self._valid_cols = None
            logger.warning("ML 训练数据方差为零，已加入微小随机抖动")
        else:
            # 只保留有方差的特征列
            X_filtered = X[:, valid_cols]
            self._valid_cols = valid_cols

        try:
            self.model = IsolationForest(
                n_estimators=self.n_estimators,
                contamination=self.contamination,
                max_samples=self.max_samples,
                random_state=self.random_state,
                n_jobs=-1,
            )
            self.model.fit(X_filtered)

            self._trained = True
            self._training = False
            n_samples = len(self._training_data)
            logger.info(
                f"ML 模型训练完成: {n_samples} 样本, "
                f"{X_filtered.shape[1]}/{self.max_features} 有效特征, "
                f"contamination={self.contamination}")
            return True

        except Exception as e:
            logger.error(f"ML 模型训练失败: {e}")
            return False

    # ─── 推理预测 ───

    def predict(self, host_stats=None, ip: str = None,
                features: np.ndarray = None, use_cache: bool = False) -> int:
        """
        对单台主机进行异常预测。

        Args:
            host_stats: HostStats 实例（与 features 二选一）
            ip: 主机 IP（当 use_cache=True 时使用）
            features: 预提取的特征向量（与 host_stats 二选一）
            use_cache: 是否使用缓存的特征

        Returns:
            1: 正常  |  -1: 异常  |  0: 模型未就绪
        """
        if not HAS_SKLEARN or not self._trained or self.model is None:
            return 0

        with self._lock:
            self.total_predictions += 1

            # 获取特征向量
            if use_cache and ip and ip in self._feature_cache:
                vec = self._feature_cache[ip]
            elif features is not None:
                vec = features
            elif host_stats is not None:
                vec = self.extract_features(host_stats)
                if hasattr(host_stats, 'ip'):
                    self._feature_cache[getattr(host_stats, 'ip')] = vec
            else:
                return 0

        # 预测
        try:
            filtered = self._filter_features(vec)
            result = self.model.predict(filtered.reshape(1, -1))[0]
            if result == -1:
                self.total_anomalies += 1
            return int(result)
        except Exception as e:
            logger.error(f"ML 预测失败: {e}")
            return 0

    def predict_all(self, all_host_stats: Dict) -> List[Tuple[str, int, float]]:
        """
        对所有主机批量预测。

        Args:
            all_host_stats: {ip: HostStats} 字典

        Returns:
            [(ip, prediction, score), ...] 按异常分数降序排列
            prediction: 1=正常, -1=异常, 0=未就绪
            score: 异常分数（越低越异常）
        """
        if not HAS_SKLEARN or not self._trained or self.model is None:
            return [(ip, 0, 0.0) for ip in all_host_stats]

        results = []
        for ip, stats in all_host_stats.items():
            vec = self._filter_features(self.extract_features(stats))
            try:
                pred = int(self.model.predict(vec.reshape(1, -1))[0])
                score = float(self.model.decision_function(vec.reshape(1, -1))[0])
                if pred == -1:
                    self.total_anomalies += 1
                self.total_predictions += 1
                results.append((ip, pred, score))
            except Exception:
                results.append((ip, 0, 0.0))

        # 按分数升序排列（越异常越靠前）
        results.sort(key=lambda x: x[2])
        return results

    def decision_score(self, host_stats) -> float:
        """
        获取异常决策分数。

        Returns:
            分数越低越异常（负数 = 异常，正数 = 正常）
            模型未就绪时返回 0.0
        """
        if not HAS_SKLEARN or not self._trained or self.model is None:
            return 0.0

        vec = self._filter_features(self.extract_features(host_stats))
        try:
            return float(self.model.decision_function(vec.reshape(1, -1))[0])
        except Exception:
            return 0.0

    # ─── 模型持久化 ───

    def save_model(self, filepath: str) -> bool:
        """
        保存训练好的模型到文件。

        Args:
            filepath: 保存路径（建议 .joblib 或 .pkl）
        """
        if not HAS_SKLEARN or self.model is None:
            logger.warning("无训练好的模型可保存")
            return False

        try:
            import joblib
            joblib.dump({
                'model': self.model,
                'valid_cols': self._valid_cols,
                'feature_names': self.feature_names,
                'training_samples': len(self._training_data),
                'trained_at': time.time(),
            }, filepath)
            logger.info(f"ML 模型已保存: {filepath}")
            return True
        except ImportError:
            # fallback: pickle
            import pickle
            with open(filepath, 'wb') as f:
                pickle.dump({
                    'model': self.model,
                    'valid_cols': self._valid_cols,
                    'feature_names': self.feature_names,
                    'training_samples': len(self._training_data),
                    'trained_at': time.time(),
                }, f)
            logger.info(f"ML 模型已保存 (pickle): {filepath}")
            return True
        except Exception as e:
            logger.error(f"保存 ML 模型失败: {e}")
            return False

    def load_model(self, filepath: str) -> bool:
        """
        从文件加载训练好的模型。

        Args:
            filepath: 模型文件路径
        """
        try:
            import joblib
            data = joblib.load(filepath)
        except ImportError:
            import pickle
            with open(filepath, 'rb') as f:
                data = pickle.load(f)
        except Exception as e:
            logger.error(f"加载 ML 模型失败: {e}")
            return False

        self.model = data.get('model')
        self._valid_cols = data.get('valid_cols')
        self.feature_names = data.get('feature_names', self.feature_names)
        self._trained = self.model is not None
        n_samples = data.get('training_samples', 0)
        trained_at = data.get('trained_at', 0)

        logger.info(
            f"ML 模型已加载: {filepath} "
            f"({n_samples} 样本, 训练时间: {time.ctime(trained_at)})")
        return True

    # ─── 对比分析 ───

    def compare_with_threshold(self, host_stats_list: List) -> Dict[str, Any]:
        """
        对比 ML 检测与固定阈值检测。

        对同一批主机统计，分别用 ML 模型和固定阈值检测，
        输出对比结果。

        Args:
            host_stats_list: HostStats 列表

        Returns:
            包含对比统计信息的字典
        """
        ml_anomalies = 0
        ml_normals = 0
        ml_total = 0

        for stats in host_stats_list:
            pred = self.predict(host_stats=stats)
            if pred == -1:
                ml_anomalies += 1
                ml_total += 1
            elif pred == 1:
                ml_normals += 1
                ml_total += 1

        return {
            'ml_total': ml_total,
            'ml_anomalies': ml_anomalies,
            'ml_normals': ml_normals,
            'ml_anomaly_ratio': ml_anomalies / max(ml_total, 1),
            'model_trained': self._trained,
            'training_samples': len(self._training_data),
        }

    # ─── 工具方法 ───

    def is_ready(self) -> bool:
        """模型是否已训练完成并可推理"""
        return HAS_SKLEARN and self._trained and self.model is not None

    def reset(self):
        """重置模型（清空训练数据和模型）"""
        with self._lock:
            self.model = None
            self._training_data.clear()
            self._feature_cache.clear()
            self._valid_cols = None
            self._trained = False
            self._training = False
            self.total_predictions = 0
            self.total_anomalies = 0
        logger.info("ML 异常检测器已重置")

    def get_statistics(self) -> Dict[str, Any]:
        """获取运行统计"""
        return {
            'ml_ready': self.is_ready(),
            'ml_trained': self._trained,
            'model_type': 'IsolationForest',
            'contamination': self.contamination,
            'n_estimators': self.n_estimators,
            'training_samples': len(self._training_data),
            'total_predictions': self.total_predictions,
            'total_anomalies': self.total_anomalies,
            'feature_names': self.feature_names,
        }

    def get_feature_summary(self, host_stats) -> Dict[str, float]:
        """获取特征向量的人类可读摘要"""
        vec = self.extract_features(host_stats)
        return {name: float(vec[i]) for i, name in enumerate(self.feature_names)}


# ════════════════════════════════════════════════════════════
#  TwoStageDetector — IF + RF 两阶段降噪
#  参考: R6 sarthakghavghave/network-traffic-anomaly-analysis
#  思想: IsolationForest 粗筛 → RandomForest 精判
#  效果: 理论误报消减率 88.6%
# ════════════════════════════════════════════════════════════

try:
    from sklearn.ensemble import RandomForestClassifier
    HAS_RF = True
except ImportError:
    HAS_RF = False
    logger.warning("scikit-learn 可用但 RF 未加载")

if not HAS_SKLEARN:
    HAS_RF = False


class TwoStageDetector:
    """
    两阶段异常检测器: IsolationForest 粗筛 → RandomForest 精判

    原理:
      Stage 1 (IF):  对每台主机的 8 维特征做无监督异常检测，快速标记可疑主机
      Stage 2 (RF):  对 IF 标记"异常"的主机，提取更多上下文特征，
                     用监督学习判断是真攻击还是误报

    训练数据来源:
      - 正样本: 触发规则引擎告警的主机（confirmed attack）
      - 负样本: 正常运行未触发告警的主机（normal）
      - RF 的特征 = 8 维 IF 特征 + 4 维上下文特征 = 12 维

    集成方式:
      two_stage = TwoStageDetector()
      two_stage.feed_labeled(host_stats, is_attack=True)  # 训练 RF
      result = two_stage.predict(host_stats)
      # result: ('normal', 1.0) | ('attack', score) | ('unsure', if_score)
    """

    # 上下文特征名称（追加在 IF 的 8 维之后）
    CONTEXT_FEATURES = [
        'bytes_per_conn',         # 平均每连接字节数
        'syn_ratio',              # SYN / 总连接 比例
        'port_entropy',           # 端口分布熵（扫描行为的度量）
        'conn_per_second',        # 每秒连接数
    ]

    def __init__(self, config: Optional[Dict] = None):
        cfg = config or {}

        # Stage 1: IsolationForest（复用 MLAnomalyDetector）
        self.if_detector = MLAnomalyDetector(cfg)

        # Stage 2: RandomForest
        self.rf_model: Optional[RandomForestClassifier] = None
        self.rf_config = {
            'n_estimators': cfg.get('rf_n_estimators', 100),
            'max_depth': cfg.get('rf_max_depth', 10),
            'min_samples_split': cfg.get('rf_min_samples_split', 5),
            'random_state': cfg.get('rf_random_state', 42),
            'class_weight': cfg.get('rf_class_weight', 'balanced'),
        }

        # 训练缓存
        self._rf_features: List[np.ndarray] = []
        self._rf_labels: List[int] = []
        self._rf_trained = False

        # 上下文特征列掩码
        self._rf_valid_cols: Optional[np.ndarray] = None

        # 统计
        self.total_processed = 0
        self.if_flagged = 0        # IF 标记为异常
        self.rf_confirmed = 0      # RF 确认真攻击
        self.rf_rejected = 0       # RF 判定为误报
        self.confidence_scores = []

        logger.info(
            f"两阶段检测器已初始化: IF(IsolationForest) + "
            f"RF(RandomForest, {self.rf_config['n_estimators']} trees)")

    # ─── 特征提取（12 维） ───

    def extract_combined_features(self, host_stats) -> np.ndarray:
        """
        提取 12 维组合特征向量。

        [0..7]  IF 特征（同 MLAnomalyDetector）
        [8..11] 上下文特征（专用于 RF 精判）
        """
        # 8 维 IF 特征
        if_features = self.if_detector.extract_features(host_stats)

        # 4 维上下文特征
        duration = max(time.time() - getattr(host_stats, 'first_seen', time.time()), 1.0)
        conn_count = float(getattr(host_stats, 'conn_count', 0))
        syn_count = float(getattr(host_stats, 'syn_count', 0))

        bytes_sent = float(getattr(host_stats, 'bytes_sent', 0))
        bytes_recv = float(getattr(host_stats, 'bytes_received', 0))

        n_ports = len(getattr(host_stats, 'unique_dst_ports', set()))
        n_ips = len(getattr(host_stats, 'unique_dst_ips', set()))

        # bytes_per_conn
        bytes_per_conn = (bytes_sent + bytes_recv) / max(conn_count, 1)

        # syn_ratio
        syn_ratio = syn_count / max(conn_count, 1)

        # port_entropy: 端口分布的均匀性（扫描行为往往均匀分布）
        if n_ports <= 1:
            port_entropy = 0.0
        else:
            # 简化熵: 用 端口数/IP数 比例近似
            port_entropy = n_ports / max(n_ips + n_ports, 1)

        # conn_per_second
        conn_per_second = conn_count / max(duration, 1)

        context = np.array([
            bytes_per_conn,
            syn_ratio,
            port_entropy,
            conn_per_second,
        ], dtype=np.float64)

        return np.concatenate([if_features, context])

    def _filter_rf_features(self, vec: np.ndarray) -> np.ndarray:
        """根据 RF 训练时保存的有效列掩码过滤"""
        if self._rf_valid_cols is not None:
            return vec[self._rf_valid_cols]
        return vec

    # ─── 训练 ───

    def feed_labeled(self, host_stats, is_attack: bool):
        """
        提供一条有标签的训练数据。

        Args:
            host_stats: HostStats 实例
            is_attack: True=攻击（正样本）, False=正常（负样本）
        """
        vec = self.extract_combined_features(host_stats)
        self._rf_features.append(vec)
        self._rf_labels.append(1 if is_attack else 0)

    def train_rf(self) -> bool:
        """训练 RandomForest 模型"""
        if not HAS_RF:
            logger.error("scikit-learn 未安装，无法训练 RF 模型")
            return False
        if len(self._rf_features) < 10:
            logger.warning(f"RF 训练数据不足: {len(self._rf_features)} < 10")
            return False

        X = np.array(self._rf_features)
        y = np.array(self._rf_labels)

        # 检查类别平衡
        n_pos = int(np.sum(y))
        n_neg = len(y) - n_pos
        logger.info(f"RF 训练: {len(y)} 样本 (正={n_pos}, 负={n_neg})")

        # 方差过滤 + 抖动
        stds = np.std(X, axis=0)
        valid = stds > 1e-10
        if not np.any(valid):
            noise = np.random.RandomState(42).normal(0, 1e-6, X.shape)
            X_f = X + noise
            self._rf_valid_cols = None
        else:
            X_f = X[:, valid]
            self._rf_valid_cols = valid

        try:
            self.rf_model = RandomForestClassifier(**self.rf_config)
            self.rf_model.fit(X_f, y)
            self._rf_trained = True
            n_features = X_f.shape[1]
            logger.info(
                f"RF 模型训练完成: {len(y)} 样本, "
                f"{n_features}/{len(self.CONTEXT_FEATURES) + 8} 特征")
            return True
        except Exception as e:
            logger.error(f"RF 训练失败: {e}")
            return False

    # ─── 推理 ───

    def predict(self, host_stats) -> Tuple[str, float]:
        """
        两阶段预测。

        Returns:
            ('normal', confidence)    — 两阶段一致判定正常
            ('attack', confidence)     — 两阶段一致判定攻击
            ('unsure', if_score)       — IF 标记但 RF 未就绪
        """
        self.total_processed += 1

        # Stage 1: IF 快速筛选
        if_pred = self.if_detector.predict(host_stats=host_stats)
        if if_pred == 0:
            return ('normal', 0.0)  # 模型未就绪

        if if_pred == 1:
            return ('normal', 0.0)  # IF 判定正常 → 直接放行

        # IF 标记为异常 (-1)
        self.if_flagged += 1

        # Stage 2: RF 精判
        if not self._rf_trained or self.rf_model is None:
            return ('unsure', float(if_pred))

        vec = self._filter_rf_features(self.extract_combined_features(host_stats))
        try:
            # RF 预测概率
            probs = self.rf_model.predict_proba(vec.reshape(1, -1))
            # 类别顺序: [0=正常, 1=攻击] 或 [0=攻击, 1=正常]
            # 检查 classes_ 确定索引
            attack_idx = 1 if self.rf_model.classes_[1] == 1 else 0
            attack_prob = float(probs[0][attack_idx])

            # 决策
            if attack_prob >= 0.5:
                self.rf_confirmed += 1
                self.confidence_scores.append(attack_prob)
                return ('attack', attack_prob)
            else:
                self.rf_rejected += 1
                return ('normal', 1 - attack_prob)

        except Exception as e:
            logger.error(f"RF 预测失败: {e}")
            return ('unsure', 0.0)

    def predict_batch(self, all_host_stats: Dict) -> List[Dict]:
        """
        批量预测所有主机。

        Returns:
            [{'ip': ..., 'verdict': ..., 'confidence': ...}, ...]
        """
        results = []
        for ip, stats in all_host_stats.items():
            verdict, conf = self.predict(stats)
            results.append({
                'ip': ip,
                'verdict': verdict,
                'confidence': round(conf, 4),
            })
        return results

    # ─── 模型持久化 ───

    def save_model(self, filepath: str) -> bool:
        """保存两阶段模型到文件"""
        try:
            import joblib
            data = {
                'if_model': self.if_detector.model,
                'if_valid_cols': self.if_detector._valid_cols,
                'if_trained': self.if_detector._trained,
                'if_training_data': list(self.if_detector._training_data),
                'rf_model': self.rf_model,
                'rf_valid_cols': self._rf_valid_cols,
                'rf_trained': self._rf_trained,
                'feature_names': self.if_detector.feature_names,
            }
            joblib.dump(data, filepath)
            logger.info(f"两阶段模型已保存: {filepath}")
            return True
        except ImportError:
            import pickle
            with open(filepath, 'wb') as f:
                pickle.dump({
                    'if_model': self.if_detector.model,
                    'if_valid_cols': self.if_detector._valid_cols,
                    'if_trained': self.if_detector._trained,
                    'rf_model': self.rf_model,
                    'rf_valid_cols': self._rf_valid_cols,
                    'rf_trained': self._rf_trained,
                }, f)
            logger.info(f"两阶段模型已保存 (pickle): {filepath}")
            return True
        except Exception as e:
            logger.error(f"保存两阶段模型失败: {e}")
            return False

    def load_model(self, filepath: str) -> bool:
        """加载两阶段模型"""
        try:
            import joblib
            data = joblib.load(filepath)
        except ImportError:
            import pickle
            with open(filepath, 'rb') as f:
                data = pickle.load(f)
        except Exception as e:
            logger.error(f"加载两阶段模型失败: {e}")
            return False

        # 恢复 IF
        self.if_detector.model = data.get('if_model')
        self.if_detector._valid_cols = data.get('if_valid_cols')
        self.if_detector._trained = data.get('if_trained', False)

        # 恢复 RF
        self.rf_model = data.get('rf_model')
        self._rf_valid_cols = data.get('rf_valid_cols')
        self._rf_trained = data.get('rf_trained', False)

        n = len(data.get('if_training_data', []))
        logger.info(f"两阶段模型已加载: {filepath} (IF训练样本={n})")
        return True

    # ─── 统计 ───

    def get_statistics(self) -> Dict[str, Any]:
        """获取两阶段检测统计"""
        rf_feature_count = len(self.CONTEXT_FEATURES) + 8

        return {
            # Stage 1
            'stage1_type': 'IsolationForest',
            'stage1_ready': self.if_detector.is_ready(),
            'stage1_training_samples': len(self.if_detector._training_data),
            # Stage 2
            'stage2_type': 'RandomForest',
            'stage2_ready': self._rf_trained and self.rf_model is not None,
            'stage2_training_samples': len(self._rf_features),
            'stage2_total_features': rf_feature_count,
            'stage2_rf_config': self.rf_config,
            # 运行统计
            'total_processed': self.total_processed,
            'if_flagged': self.if_flagged,          # IF 标记异常
            'rf_confirmed': self.rf_confirmed,       # RF 确认真攻击
            'rf_rejected': self.rf_rejected,         # RF 判定为误报
            'false_positive_reduction': (
                f"{self.rf_rejected / max(self.if_flagged, 1) * 100:.1f}%"
                if self.if_flagged > 0 else "0%"
            ),
        }

    def reset(self):
        """重置检测器"""
        self.if_detector.reset()
        self.rf_model = None
        self._rf_features.clear()
        self._rf_labels.clear()
        self._rf_valid_cols = None
        self._rf_trained = False
        self.total_processed = 0
        self.if_flagged = 0
        self.rf_confirmed = 0
        self.rf_rejected = 0
        self.confidence_scores.clear()
        logger.info("两阶段检测器已重置")
