# output/ — 运行时输出文件

> 此目录存放系统运行时自动生成的文件。**所有内容已在 `.gitignore` 中排除**，不会提交到 Git。

## 文件说明

| 文件 | 来源模块 | 触发条件 | 用途 |
|------|----------|----------|------|
| `alerts.json` | `core/alert_manager.py` | `enable_json_export: true` | 告警 JSON 持久化，追加写入，上限 10000 条 |
| `alerts.log` | `core/alert_manager.py` | `enable_file_log: true` | 告警管理器关闭时的统计日志 |
| `logs/ids.log` | `utils/logger.py` → `main.py` | 始终开启 | 系统运行日志（所有模块的 logging 输出） |
| `blacklist.txt` | `tools/threat_intel.py`（扩展） | `threat_intel.enabled: true` | 本地 IP 黑名单（每行一个 IP） |

## 清理

```bash
# 清空所有运行时输出（不影响源代码和测试数据）
rm output/alerts.json output/alerts.log output/logs/*.log
```

## 配置

所有输出路径在 `config.yaml` 中配置，修改后重启生效：

```yaml
system:
  log_dir: "./output/logs"
  log_file: "ids.log"

alert:
  json_export_file: "./output/alerts.json"
  log_file: "./output/alerts.log"

threat_intel:
  local_blacklist: "./output/blacklist.txt"
```
