# ============================================================
# 模块: 配置加载器 (config_loader.py)
# 功能: 统一读取和验证 YAML 配置文件
# ============================================================

import os
import yaml
from typing import Dict, Any, Optional


class ConfigLoader:
    """配置文件加载与验证"""

    DEFAULT_CONFIG = {
        'capture': {
            'interface': None,
            'filter_rule': 'tcp',
            'promiscuous': True,
            'snaplen': 65535,
        },
        'signatures': {'directory': './signatures'},
        'anomaly': {
            'time_window': 60,
            'port_scan': {'unique_ports_threshold': 20},
            'horizontal_scan': {'unique_ips_threshold': 50},
            'brute_force': {'login_fail_threshold': 5},
            'syn_flood': {'syn_threshold': 1000, 'syn_ratio': 0.8},
        },
        'tcp_reassembly': {
            'enabled': True,
            'stream_timeout': 300,
            'max_stream_size': 10485760,
            'max_concurrent_streams': 1000,
        },
        'alert': {
            'enable_console_output': True,
            'enable_json_export': True,
            'json_export_file': './alerts.json',
            'dedup_window': 10,
        },
    }

    @classmethod
    def load(cls, config_path: str = 'config.yaml') -> Dict[str, Any]:
        """加载配置，合并默认值"""
        config = cls.DEFAULT_CONFIG.copy()

        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                user_config = yaml.safe_load(f)
            if user_config:
                cls._deep_merge(config, user_config)

        return config

    @classmethod
    def _deep_merge(cls, base: Dict, override: Dict):
        """深度合并字典"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                cls._deep_merge(base[key], value)
            else:
                base[key] = value

    @classmethod
    def get_capture_config(cls, config: Dict) -> Dict:
        return config.get('capture', {})

    @classmethod
    def get_anomaly_config(cls, config: Dict) -> Dict:
        return config.get('anomaly', {})

    @classmethod
    def get_alert_config(cls, config: Dict) -> Dict:
        return config.get('alert', {})
