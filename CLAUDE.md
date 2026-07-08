# NADS — 常见网络攻击检测系统 开发规范

> **项目**: Network Attack Detection System
> **语言**: Python 3.9+
> **平台**: Windows / Linux

---

## 1. 项目概述

基于**误用检测（签名匹配）+ 异常检测（基线偏离）**的混合入侵检测系统。

```
数据包 → PacketCapture → ProtocolParser → TCPReassembler
                        ↓                       ↓
                  AnomalyDetector         MisuseDetector
                        ↓                       ↓
                        └───────┬───────────────┘
                                ↓
                          AlertManager → GUI
```

### 模块归属（不可跨成员修改）

| 模块 | 负责人 | 文件 |
|------|--------|------|
| 误用检测 + 集成 | **成员A** | `main.py`, `core/misuse_detector.py`, `signatures/*.yaml` |
| 数据采集 + 协议 | **成员B** | `core/packet_capture.py`, `core/protocol_parser.py`, `core/tcp_reassembler.py` |
| 异常检测 + 基线 | **成员C** | `core/anomaly_detector.py`, `core/baseline_learner.py` |
| GUI + 告警 + 测试 | **成员D** | `gui/main_window.py`, `core/alert_manager.py`, `tests/`, `docs/` |

---

## 2. 环境搭建

```bash
# 1. 创建虚拟环境
python -m venv venv

# 2. 激活 (Windows)
venv\Scripts\activate
# 激活 (Linux/Mac)
source venv/bin/activate

# 3. 安装依赖
pip install -r requirements.txt

# 4. Windows 额外步骤：安装 Npcap
# 下载 https://npcap.com/#download
# 安装时勾选 "Install Npcap in WinPcap API-compatible Mode"

# 5. 验证
python -c "import scapy; print('Scapy OK')"
python -c "import yaml; print('YAML OK')"
python -c "import PyQt5; print('PyQt5 OK')"
```

---

## 3. 目录结构（不可随意改动）

```
./
├── main.py                  # 入口 + IDSEngine（成员A）
├── config.yaml              # 全局配置
├── requirements.txt         # 依赖清单
├── .gitignore               # Git 忽略规则
│
├── core/                    # 核心引擎模块
│   ├── __init__.py
│   ├── packet_capture.py    # 数据包捕获（成员B）
│   ├── protocol_parser.py   # 协议解析（成员B）
│   ├── tcp_reassembler.py   # TCP 流重组（成员B）
│   ├── misuse_detector.py   # 误用检测引擎（成员A）
│   ├── anomaly_detector.py  # 异常检测引擎（成员C）
│   ├── baseline_learner.py  # 基线学习器（成员C）
│   └── alert_manager.py     # 告警管理器（成员D）
│
├── signatures/              # 攻击特征库（成员A）
│   ├── sql_injection.yaml
│   ├── xss.yaml
│   ├── web_attack.yaml
│   ├── brute_force.yaml
│   ├── backdoor.yaml
│   ├── scan.yaml
│   └── dos.yaml
│
├── gui/                     # 用户界面（成员D）
│   ├── __init__.py
│   └── main_window.py
│
├── utils/                   # 工具模块
│   ├── __init__.py
│   ├── config_loader.py
│   └── logger.py
│
├── tests/                   # 测试（成员D）
│   ├── __init__.py
│   ├── test_signature_match.py
│   └── test_pcaps/
│
├── docs/                    # 文档（成员D）
│   ├── 团队分工文档.md
│   ├── README.md
│   └── 答辩PPT大纲.md
│
└── reference/               # 课程资料（不提交 Git）
```

---

## 4. 代码规范

### 4.1 命名规则

```python
# 类名: PascalCase
class PacketCapture:
    pass

# 函数/方法/变量: snake_case
def parse_packet(self, raw_data: bytes) -> dict:
    parsed_result = {}
    return parsed_result

# 常量: UPPER_CASE
MAX_PACKET_SIZE = 65535
DEFAULT_TIMEOUT = 60

# 私有成员: 前缀单下划线
self._running = False
self._lock = threading.RLock()

# 模块级私有: 前缀双下划线
__version__ = "1.0.0"
```

### 4.2 类型标注（必须）

所有公开方法和函数的参数和返回值**必须标注类型**：

```python
from typing import Dict, List, Optional, Any, Callable, Tuple

def match_packet(self, parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    """对单个已解析的数据包进行特征匹配"""
    ...

def get_statistics(self, hours: int = 24) -> Dict[str, Any]:
    """获取告警统计报告"""
    ...
```

### 4.3 文档字符串（必须）

每个公开类和方法必须有 docstring（Google 风格）：

```python
def update(self, parsed: Dict[str, Any]) -> None:
    """
    根据一个已解析的数据包更新统计指标。

    Args:
        parsed: ProtocolParser.parse() 的返回结果，必须包含:
            - src_ip: 源IP地址
            - dst_ip: 目标IP地址
            - dst_port: 目标端口
            - flags: TCP标志位

    Returns:
        None

    Raises:
        KeyError: 如果 parsed 缺少必要字段
    """
    ...
```

### 4.4 日志

- **禁止**使用 `print()` 进行调试输出
- **必须**使用 `logging` 模块：

```python
import logging
logger = logging.getLogger(__name__)

logger.debug("详细调试信息")
logger.info("一般信息")
logger.warning("警告")
logger.error("错误")
```

### 4.5 导入顺序

```python
# 1. 标准库
import os
import sys
import time
from typing import Dict, List

# 2. 第三方库
import yaml
from scapy.all import sniff

# 3. 项目内部模块
from core.protocol_parser import ProtocolParser
from core.alert_manager import AlertManager
```

---

## 5. 接口约定（不可随意修改字段名）

### 5.1 parsed_packet（成员B 输出 → 成员A/C 消费）

```python
parsed = {
    'src_ip':       str,        # 源IP
    'dst_ip':       str,        # 目标IP
    'src_port':     int,        # 源端口
    'dst_port':     int,        # 目标端口
    'seq':          int,        # TCP序列号
    'ack':          int,        # TCP确认号
    'flags':        int,        # TCP标志位（原始值）
    'flags_str':    str,        # TCP标志位（可读，如 "PA", "S"）
    'payload':      bytes,      # TCP载荷
    'payload_len':  int,        # 载荷长度
    'app_protocol': AppProtocol,# 应用层协议
    'http_method':  str|None,   # HTTP方法
    'http_uri':     str|None,   # HTTP URI
    'http_host':    str|None,   # HTTP Host头
    'http_user_agent': str|None,# HTTP User-Agent
    'timestamp':    float,      # 时间戳
}
```

### 5.2 alert（成员A/C 输出 → 成员D 消费）

```python
alert = {
    'signature_id':     str,    # 规则ID，如 "SQLI-001"
    'signature_name':   str,    # 规则名称
    'type':             str,    # 具体类型
    'category':         str,    # 大类
    'severity':         str,    # critical|high|medium|low
    'description':      str,    # 人类可读描述
    'src_ip':           str,
    'dst_ip':           str,
    'src_port':         int,
    'dst_port':         int,
    'matched_pattern':  str,    # 匹配到的模式
    'matched_text':     str,    # 匹配到的原文（截断100字符）
    'timestamp':        float,
    'detail':           dict,   # 可选，额外详情
}
```

### 5.3 接口变更流程

**任何人修改上述字段名或格式之前，必须：**
1. 在团队群中发消息说明变更内容和原因
2. 等待下游消费者（成员）确认
3. 同时更新本文档

---

## 6. Git 规范

### 6.1 分支策略

```
main                  # 稳定主分支（成员A 管理合并）
  ├── feat/a-xxx      # 成员A 的功能分支
  ├── feat/b-xxx      # 成员B 的功能分支
  ├── feat/c-xxx      # 成员C 的功能分支
  └── feat/d-xxx      # 成员D 的功能分支
```

### 6.2 Commit 格式

```
<type>: <简短描述>

类型:
  feat:     新功能
  fix:      修bug
  docs:     文档更新
  test:     测试相关
  refactor: 重构（不改变功能）
  perf:     性能优化
  chore:    杂项（配置、依赖等）
  style:    代码格式

示例:
  feat: 增加 AC 自动机多模式匹配支持
  fix: 修复 ProtocolParser 对 IPv6 包的解析崩溃
  docs: 更新接口约定文档中 alert 格式
  test: 增加 SQL 注入检测的 10 个测试用例
```

### 6.3 不要提交的文件

`reference/` 目录已加入 `.gitignore`。以下内容也**不要提交**：
- 虚拟环境 `venv/`
- `__pycache__/`
- `.pyc` 编译文件
- `logs/`, `*.log`
- `alerts.json` 测试产生的告警数据
- IDE 配置 `.idea/`, `.vscode/`

---

## 7. 测试规范

### 7.1 如何运行测试

```bash
# 在项目根目录下运行
python -m pytest tests/ -v

# 或单独运行某个测试
python tests/test_signature_match.py
```

### 7.2 每个成员的最小测试要求

- **成员A**: `tests/test_signature_match.py` 全部通过，准确率 > 90%
- **成员B**: 能在本机抓到 10 个 TCP 包并正确解析
- **成员C**: 模拟端口扫描能触发告警，模拟暴力破解能触发告警
- **成员D**: GUI 窗口能打开不崩溃，`alert_manager` 去重逻辑正确

### 7.3 PCAP 回放测试

```bash
# 把测试用 PCAP 放到 tests/test_pcaps/ 目录
python main.py --replay tests/test_pcaps/attack_sample.pcap
```

---

## 8. Agent 开发协作规范

本项目使用 Claude Code Agent 辅助开发。以下是使用 Agent 的规范：

### 8.1 每个成员独立工作在自己的文件上

```
使用 Agent 时，始终明确指定你要修改的文件路径。
不要让 Agent 修改其他成员负责的文件。
如果不确定某个改动是否影响他人，先在群内确认。
```

### 8.2 使用 Agent 的典型工作流

```
第1步: 先读代码理解现状
  "读取 core/misuse_detector.py，帮我理解 match_packet 方法的当前逻辑"

第2步: 明确要改什么
  "在 _build_indices 方法中增加按阈值的预处理逻辑"

第3步: 让 Agent 修改代码，但只改你的文件
  "修改 core/misuse_detector.py 的 _build_indices 方法，增加..."

第4步: 修改后立即运行测试验证
  "运行 tests/test_signature_match.py 验证改动是否正确"

第5步: 如果测试失败，让 Agent 看错误日志修 bug
  "测试输出显示 XXX 报错，帮我修"
```

### 8.3 不依赖 Agent 的场景（必须手写）

- **接口格式变更**（影响其他成员）→ 先在群里沟通，再改代码和本文档
- **目录结构调整** → 必须全员同意
- **新增依赖** → 必须在 `requirements.txt` 中写明，全员 `pip install`

### 8.4 Agent 提示词模板

```markdown
# 给 Agent 的好提示:
"在 core/misuse_detector.py 中，我只想改 SignatureMatcher 类。
不要动文件中的其他类。改完后在 main.py 的 IDSEngine.__init__
中确认初始化的参数名对应。"

# 给 Agent 的坏提示:
"帮我优化一下性能"                    # 太模糊
"帮我改一下整个检测引擎"               # 范围太大，可能动别人的代码
```

---

## 9. 性能基准

| 指标 | 目标 | 测试方式 |
|------|------|----------|
| 特征匹配延迟 | < 1ms/包 | 10000 包批量测试 |
| 抓包 PPS | > 5000 pps | PCAP 高速回放 |
| GUI 刷新延迟 | < 100ms | 1秒定时器正常刷新 |
| 内存占用 | < 500MB | 长时间运行监控 |

---

## 10. 常见问题

### Q: 导入报错 `ModuleNotFoundError: No module named 'core'`
**A:** 在项目根目录运行 Python，或者添加：
```python
import sys; sys.path.insert(0, '.')
```

### Q: Scapy 抓包报权限错误（Windows）
**A:** 以管理员身份运行终端 + 安装 Npcap（勾选 WinPcap 兼容模式）

### Q: pyahocorasick 安装失败
**A:** 代码有内置 fallback（SimpleMultiPatternMatcher），不影响运行，只是慢一点

### Q: GUI 打不开
**A:** `pip install pyqt5 pyqtchart`，如果还不行，检查是否在虚拟环境中

---

> **最后更新**: 2026-07-08
> **维护者**: 成员A（项目负责人）
> **变更记录**: 创建项目规范文档，定义接口和代码风格
