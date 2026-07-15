# 成员B 开发日志 — 数据采集 + 协议解析 + TCP 流重组

> **负责模块**: `core/packet_capture.py`, `core/protocol_parser.py`, `core/tcp_reassembler.py`
> **角色**: 网络数据采集
> **开始日期**: 2026-07-08

---

## Day 1 — 2026-07-08 (环境搭建 + 抓包测试)

### 1. 今日进度

- [x] 安装 Npcap（Windows），Scapy 能枚举 Npcap 网络接口
- [x] 验证 `from scapy.all import sniff` 可用
- [x] 测试抓包：能抓到 10 个 TCP 包并打印摘要
- [x] 测试协议解析：构造假 HTTP 包，验证 `ProtocolParser.parse()` 输出格式

### 2. 遇到的问题与解决

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| 安装依赖后出现 pip 版本更新 notice | pip 提示有新版本，不是安装错误 | 暂不升级，先验证项目依赖是否能正常导入 |
| 将 `print(...)` 单独粘贴到 PowerShell 后报错 | 该语句是 Python 代码，PowerShell 无法按 Python 语法执行 | 使用完整的 `python -c "..."` 命令，并在项目根目录导入 `PacketCapture` |
| 文档预期 HTTP 载荷长度为 54，实际输出为 47 | 文档中的字节数计算有误 | 按实际 `Raw(load=...)` 字节串复核，确认正确长度为 47 |

### 3. Agent 协作记录

| 任务 | 是否用 Agent | 效果评估 |
|------|-------------|----------|
| 阅读开发规范、成员分工和成员 B 负责模块 | 是 | 明确了环境搭建、抓包、解析和流重组的验收顺序 |
| 排查 PowerShell 命令报错并整理可直接执行的命令 | 是 | 区分了 PowerShell 与 Python 代码，完成网卡枚举和抓包测试 |
| 核对 HTTP 模拟包的预期输出 | 是 | 发现并纠正文档中的载荷长度错误 |

### 4. 技术决策

| 决策 | 选项 A | 选项 B | 选择 | 理由 |
|------|--------|--------|------|------|
| 抓包库选择 | Scapy + Npcap | 原生 libpcap/pypcap | Scapy + Npcap | 与项目现有实现和依赖一致，接口清晰，便于快速验证 |
| 环境验证方式 | 分层验证 | 直接运行完整系统 | 分层验证 | 依次验证依赖、Npcap、项目抓包类和解析器，便于定位故障 |

### 5. 性能/测试数据

| 测试项 | 结果 | 备注 |
|--------|------|------|
| 抓包成功 | 成功，10 个 TCP 包 | Scapy 能识别多个 `NPF_{...}` 接口及 `NPF_Loopback` |
| HTTP 模拟包解析 | 成功，1/1 | Method=`GET`，URI=`/index.html`，Host=`example.com`，载荷 47 字节 |
| 协议识别种类 | 代码声明支持 9 种，当前实测 1 种 | 已实测 HTTP，其余协议待验证 |
| 解析单包耗时 | 待测 | 尚未进行性能基准测试 |

### 6. 参考项目借鉴

| 参考项目 | 借鉴内容 | 落地情况 |
|----------|----------|----------|
| / | 本阶段未开展开源项目调研 | 待后续补充 |

### 7. 明日计划

- [ ] 将真实抓到的 TCP 包送入 `ProtocolParser`，验证采集与解析链路
- [ ] 测试并完善 TCP 流重组对乱序、重传和重叠分片的处理

---

## Day 2 — 2026-07-09 (协议解析完善 + TCP 流重组)

### 1. 今日进度

- [x] 使用两个模拟 TCP 分片测试 `TCPStreamReassembler.feed()`
- [x] 成功将 `UNION SE` 和 `LECT` 重组为完整的 `UNION SELECT`
- [x] 阅读流重组实现，确认当前序列号处理能力和后续改进点
- [x] 修复 Windows Npcap 后端启动异步抓包时不支持 `snaplen` 参数的问题

### 2. 遇到的问题与解决

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| 分工文档将第二个分片的序列号写为 118 | 第一个分片从 100 开始且长度为 19，下一序列号计算错误 | 测试时改为正确的 `seq=119` |
| 当前重组器接收 `seq` 但未按序列号排序 | `StreamBuffer.add_segment()` 直接追加载荷，尚未实现乱序、重传和重叠处理 | 已记录为成员 B 后续开发重点，先补测试再完善实现 |
| Windows 异步抓包在 `stop()` 时抛出 `unexpected keyword argument 'snaplen'` | `AsyncSniffer` 将该参数传给 Npcap 的 `L2pcapListenSocket`，但此后端不支持该参数 | 不再向 `AsyncSniffer` 传递 `snaplen`，保留 `PacketCapture` 构造参数以维持接口兼容 |

### 3. Agent 协作记录

| 任务 | 是否用 Agent | 效果评估 |
|------|-------------|----------|
| 阅读并解释 TCP 流重组代码 | 是 | 明确了四元组聚合、流缓存和跨包特征恢复流程 |
| 复核测试数据中的 TCP 序列号 | 是 | 发现文档中的 118 应为 119，并识别出现有实现限制 |
| 定位 Windows 异步抓包异常 | 是 | 根据堆栈定位到 Scapy 后端参数不兼容，并完成最小范围修复 |

### 4. 技术决策

| 决策 | 选项 A | 选项 B | 选择 | 理由 |
|------|--------|--------|------|------|
| 流重组测试顺序 | 先验证顺序分片 | 直接测试复杂乱序流量 | 先验证顺序分片 | 先建立可重复的基础测试，再逐步覆盖乱序、重传和重叠情况 |

### 5. 性能/测试数据

| 测试项 | 结果 | 备注 |
|--------|------|------|
| TCP 流重组测试 | 分片包数 2 → 完整流 47 字节 | 成功恢复 `UNION SELECT`，创建 1 条活动流 |
| 乱序/重传处理 | 待测 | 当前实现仅按到达顺序追加载荷 |
| 协议指纹识别准确率 | 待测 | 尚未使用真实 PCAP 与 Wireshark 对比 |

### 6. 参考项目借鉴

| 参考项目 | 借鉴内容 | 落地情况 |
|----------|----------|----------|
| / | 本阶段未开展开源项目调研 | 待后续补充 |

### 7. 明日计划

- [ ] 完成真实抓包与 `ProtocolParser` 联调
- [ ] 为乱序、重传和重叠分片设计可重复测试用例

---

## Day 3 — 2026-07-10

（复制 Day 2 的模板，继续填写）

---

## Day 4 — 2026-07-11

---

## Day 5 — 2026-07-12

### 1. 今日进度

- [x] 使用 Wireshark 抓取并保存 120.35 秒真实网络流量，共 2796 个包
- [x] 使用 `ProtocolParser` 批量解析 PCAP 中的 1301 个 TCP 包
- [x] 修复无 `Raw` 载荷的 TCP 控制包被误判为 `unparsed` 的问题
- [x] 完成项目解析结果与 Wireshark 逐包协议标注对比
- [x] 完成单包解析耗时与吞吐量基准测试

### 2. 遇到的问题与解决

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| 首次批量分析有 360/1301 个 TCP 包返回 `None` | `ProtocolParser.parse()` 使用 `hasattr(raw_packet, 'load')` 判断 Scapy 对象，无载荷的 ACK/FIN 包没有 `Raw/load` 层 | 改用所有 Scapy 包均具备的 `getlayer` 判断，再由现有逻辑解析 IP/TCP 头；修复后 1301/1301 均成功解析 |
| Wireshark 显示 `TLSv1.2/TLSv1.3/SSL`，项目显示 `HTTPS/TLS` | Wireshark按实际解码层命名，项目还会根据 443 端口进行协议归类 | 对比时将 `HTTPS` 和 `TLS` 归为 TLS/HTTPS 协议族，避免把命名粒度差异误算为错误 |
| Wireshark 有 723 个包只标为 `TCP` | ACK 等控制包没有可供 Wireshark继续解码的应用层载荷 | 将其纳入 TCP 头解析覆盖率，不纳入应用层协议准确率分母 |

### 3. Agent 协作记录

| 任务 | 是否用 Agent | 效果评估 |
|------|-------------|----------|
| 对 PCAP 同时运行 TShark 与项目解析器统计 | 是 | 自动定位 360 个 `unparsed` 全部为无载荷 TCP 控制包 |
| 修复 Scapy 包入口判断并复测 | 是 | TCP 解析覆盖率从 72.33% 提升到 100% |
| 生成逐包协议交叉表和性能基准 | 是 | 得到可直接用于答辩的准确率、耗时和 PPS 数据 |

### 4. 技术决策

| 决策 | 选项 A | 选项 B | 选择 | 理由 |
|------|--------|--------|------|------|
| Scapy 对象识别 | 检查 `load` 属性 | 检查 `getlayer` 方法 | `getlayer` | TCP 控制包没有 `Raw/load`，但所有 Scapy Packet 都提供 `getlayer`，覆盖范围正确且不改变公开接口 |
| 准确率统计口径 | 将 Wireshark 的 `TCP` 当应用协议 | 仅统计有明确 HTTP/TLS/SSL 标注的包 | 仅统计明确应用层标注 | 纯 ACK 包没有应用层证据，不应参与应用协议准确率计算 |

### 5. 性能/测试数据

| 测试项 | 结果 | 备注 |
|--------|------|------|
| PCAP 基本信息 | 2796 包，120.35 秒，1.86 MB | 真实网络流量，严格时间有序 |
| TCP 数据构成 | 1301 包 | IPv4 TCP 1141，IPv6 TCP 160 |
| 修复前 TCP 解析覆盖率 | 941/1301，72.33% | 360 个无载荷控制包被误判为 `unparsed` |
| 修复后 TCP 解析覆盖率 | 1301/1301，100% | IPv4、IPv6、有载荷及无载荷包均成功解析 |
| 应用协议识别准确率 | 578/578，100% | Wireshark 明确标注的 HTTP、TLSv1.x、SSL 包；`HTTPS/TLS` 按同一协议族比较 |
| 平均单包解析耗时 | 18.42 μs | 1301 个 TCP 包，重复 20 轮取平均 |
| 平均解析吞吐量 | 54293 pps | 仅测解析器，不包含磁盘读取和实时抓包开销 |

### 6. 参考项目借鉴

| 参考项目 | 借鉴内容 | 落地情况 |
|----------|----------|----------|
| Wireshark/TShark 4.6.4 | 使用协议层次统计和逐包 `_ws.col.Protocol` 作为项目解析器的对照基准 | 已完成 1301 个 TCP 包交叉对比，并明确应用层准确率统计口径 |

### 7. 明日计划

- [ ] 为 `TCPStreamReassembler` 增加乱序、重传和重叠分片测试
- [ ] 根据测试结果完善按 TCP 序列号重组逻辑

---

## Day 6 — 2026-07-13

### 1. 今日进度

- [x] 阅读课程 PDF 第 19 页加密流量检测要求，明确必做范围
- [x] 新增 `core/tls_detector.py`，实现 TLS ClientHello/ServerHello 结构化解析
- [x] 实现标准 JA3 字符串与 MD5 指纹，支持 GREASE 值过滤
- [x] 实现 TLS 1.2/1.3 Certificate 握手首证书提取与 X.509 异常检测
- [x] 实现旧 TLS 版本、RC4/DES/3DES/NULL 弱套件和异常证书检测
- [x] 内置 Trickbot、Emotet、Cobalt Strike/Metasploit 三类已知 JA3 示例指纹
- [x] 使用真实 PCAP 与 Wireshark/TShark 的 JA3 结果逐条对比

### 2. 遇到的问题与解决

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| 大多数真实 ClientHello 无法直接从单帧 `tcp.payload` 解析 | ClientHello 跨多个 TCP 段，单帧载荷不完整 | 使用 TCP 重组数据输入 `TLSDetector`；检测器支持在连续多个 TLS record 中定位目标握手消息 |
| 部分重组流在 ClientHello 前包含 ChangeCipherSpec record | 原实现只检查第一条 TLS record | 遍历连续 TLS records 和其中的 Handshake 消息，直到找到指定消息类型 |
| Python 3.13 移除了 `ssl.match_hostname` | 项目虚拟环境使用 Python 3.13 | 内部实现 SAN/CN 的 DNS、IP 和左侧单标签通配符匹配 |
| 单独使用 Cobalt Strike JA3 可能误报 | 该示例指纹也可能来自 Meterpreter 或合法 Windows SChannel | 在指纹元数据中标记低置信度，要求结合 JA3S、目标地址和流量上下文判断 |

### 3. Agent 协作记录

| 任务 | 是否用 Agent | 效果评估 |
|------|-------------|----------|
| 核对课程 PDF、TLS RFC 和 JA3 原始资料 | 是 | 将必做需求拆分为 JA3、握手异常、证书异常和恶意指纹四个可测试模块 |
| 实现并调试 TLS 二进制结构解析 | 是 | 处理长度字段、GREASE、多 record 和 TCP 重组边界 |
| 使用真实 PCAP 与 TShark 交叉验证 | 是 | 17/17 个 ClientHello 的 JA3 与 Wireshark 完全一致 |

### 4. 技术决策

| 决策 | 选项 A | 选项 B | 选择 | 理由 |
|------|--------|--------|------|------|
| JA3 解析 | 依赖 Wireshark/TShark | 项目内自主解析 ClientHello | 项目内自主解析 | 运行时不依赖外部程序，同时用 TShark 作为测试基准 |
| 证书解析 | 手写 ASN.1/X.509 | 使用 `cryptography` | `cryptography` | 避免高风险的 ASN.1 手工解析，并支持可靠的签名、公钥和 SAN 读取 |
| TLS 代理解密 | 本阶段引入 mitmproxy | 先完成非解密指纹与证书检测 | 先完成指纹与证书检测 | 代理解密属于高阶能力，涉及证书信任和流量代理部署，不应伪装成已完成 |

### 5. 性能/测试数据

| 测试项 | 结果 | 备注 |
|--------|------|------|
| 真实 JA3 对比 | 17/17，100% 一致 | 与 Wireshark 4.6.4 `tls.handshake.ja3` 对比 |
| 真实证书检测 | 通过 | 从完整 TLS Certificate 握手提取 `CN=sjtu.edu.cn`，有效期和主机名均正常 |
| 异常证书测试 | 3/3 触发 | 自签名、已过期、RSA 1024 位弱密钥 |
| 弱握手测试 | 2/2 触发 | TLS 1.0 旧版本、RC4 弱密码套件 |
| 恶意 JA3 示例库 | 3 条 | Trickbot、Emotet、Cobalt Strike/Metasploit |

### 6. 参考项目借鉴

| 参考项目 | 借鉴内容 | 落地情况 |
|----------|----------|----------|
| Salesforce JA3 | JA3 五字段顺序、MD5 计算、GREASE 排除及 Trickbot/Emotet 示例 | 已完成自主 JA3 解析并通过 17 个真实 ClientHello 对照 |
| RFC 5246 / RFC 8446 | TLS 1.2/1.3 ClientHello、ServerHello 和 Certificate 消息结构 | 已支持 TLS 1.2/1.3 相关长度字段和证书列表结构 |
| Salesforce JA3/JA3S 工程文章 | Cobalt Strike 与 Meterpreter 的 JA3/JA3S 联合判断及误报风险 | 内置示例指纹并记录低置信度与上下文关联要求 |

### 7. 明日计划

- [ ] 与成员 A/C 确认是否在 `parsed_packet` 中增加可选 `tls_analysis` 字段
- [ ] 完成 TLSDetector 与主检测流水线集成，避免擅自变更跨成员接口
- [ ] 继续实现 TCP 严格序列号重组，为跨段 ClientHello 自动检测提供完整流数据

---

## Day 7 — 2026-07-14

### 1. 今日目标

- [x] 完成成员B第三层拓展1：TCP 流严格重组
- [x] 修复 `StreamBuffer.add_segment()` 简单拼接导致的乱序包误重组问题
- [x] 增加按 TCP `seq` 排序、乱序缓存、重传去重、重叠片段裁剪能力
- [x] 将重组流从双向归一化 key 调整为方向敏感 key，避免两个方向的 TCP 序列号空间混在一起

### 2. 实现内容

| 模块 | 改动 | 说明 |
|------|------|------|
| `core/tcp_reassembler.py` | 重写 `StreamBuffer.add_segment()` | 不再直接 append，而是根据 `seq` 判断顺序、乱序、重传和重叠 |
| `StreamBuffer.segments` | 新增乱序缓存 | `seq > expected_seq` 时先缓存，等待缺失片段到达 |
| `expected_seq` / `data_start_seq` | 新增序列号边界 | 记录当前已重组流的起点和下一个期望序列号 |
| `TCPStreamReassembler.feed()` | 改用方向敏感 flow key | TCP 两个方向各自维护独立序列号，严格重组不能混用双向归一化 key |
| 统计信息 | 新增乱序、重传、重叠统计 | `get_stream_info()` 和 `get_stats()` 可展示重组质量 |

### 3. 验证结果

| 测试场景 | 输入顺序 | 预期结果 | 实际结果 |
|----------|----------|----------|----------|
| 顺序分片 | `UNION ` -> `SELECT` | `UNION SELECT` | 通过 |
| 乱序分片 | `SELECT` -> `UNION ` | `UNION SELECT` | 通过 |
| 中间缺口后到 | `Hello` -> `!!!` -> `World` | `HelloWorld!!!` | 通过 |
| 完整重传 | `HelloWorld` 重复发送 | 不重复追加 | 通过 |
| 部分重叠 | `HelloWorld` + `World!!!` | 裁剪重叠后得到 `HelloWorld!!!` | 通过 |
| 双向流分离 | 请求方向 `GET /`，响应方向 `HTTP/1.1` | 两条独立流 | 通过 |
| 语法检查 | `python -m compileall -q core` | 无语法错误 | 通过 |

### 4. 技术决策

| 决策点 | 选择 | 原因 |
|--------|------|------|
| 流 key | 使用方向敏感四元组 | TCP 序列号只在单方向内连续，双向归一化会把请求和响应的 seq 混在一起 |
| 乱序处理 | 先缓存，等缺口补齐后再 flush | 可恢复攻击者拆分在多个 TCP 包中的特征，降低分片逃避风险 |
| 重传处理 | 完整重传忽略，部分重叠裁剪 | 避免重复数据污染应用层检测结果 |
| 共享接口 | 不修改 `parsed_packet` | 只消费已有字段 `src_ip/dst_ip/port/seq/payload`，不影响 A/C |

### 5. 答辩话术

TCP 流严格重组的价值是防止攻击者把攻击特征拆散到多个 TCP 包里逃避单包检测。旧实现只是按到达顺序拼接，遇到乱序或重传会出错；现在按照 TCP 序列号重组，乱序片段会先缓存，缺失片段到达后自动合并，同时对重传和重叠片段去重。这样后续 SignatureEngine 或 TLSDetector 拿到的是更接近真实应用层字节流的数据。

### 6. 拓展2：更多协议支持

- [x] 新增 POP3、IMAP、Redis、MongoDB 协议枚举
- [x] 新增常见端口识别：POP3 110/995、IMAP 143/993、Redis 6379、MongoDB 27017/27018/27019、SMTP 465
- [x] 新增应用层指纹：SMTP `EHLO/HELO/MAIL FROM/RCPT TO/DATA`，POP3 `USER/PASS/+OK/-ERR/CAPA`，IMAP `CAPABILITY/LOGIN/* OK`，Redis RESP `PING/AUTH/PONG/NOAUTH`
- [x] 新增 MongoDB wire protocol 头部识别：解析 little-endian messageLength 和 opCode
- [x] 修复 `USER` 同时可能属于 FTP/POP3 的歧义，结合端口上下文判断
- [x] 让原始 IPv4/TCP bytes 解析路径也执行端口和指纹识别

| 测试场景 | 结果 |
|----------|------|
| SMTP `EHLO` | 识别为 SMTP |
| POP3 `USER` on 110 | 识别为 POP3 |
| FTP `USER` on 21 | 识别为 FTP |
| IMAP `CAPABILITY` | 识别为 IMAP |
| Redis RESP `PING` | 识别为 Redis |
| MongoDB opCode 2013 | 识别为 MongoDB |
| raw bytes HTTP | 识别为 HTTP，并提取 method/host |
| `python -m compileall -q core` | 通过 |

---

## 答辩素材汇总（Day 7 填写）

### 我解决的 3 个最有价值的问题

1. 
2. 
3. 

### 我的 3 个关键技术贡献

1. 
2. 
3. 

### 我从开源项目中学到的 3 点

1. 
2. 
3. 

### 答辩时可以展示的性能数据

| 指标 | 数值 |
|------|------|
| 支持的协议识别种类 | ___ 种 |
| 协议识别准确率 | ___% |
| 抓包 PPS 处理能力 | ___ pps |
| TCP 流重组延迟 | ___ ms |
| 单包解析耗时 | ___ μs |

### 我负责模块的架构图（抓包→解析→流重组的流水线）

（粘贴在此）

### Agent 使用总结

- 总共使用 Agent 协助 __ 次
- 节省了约 __ 小时的开发时间
- 最有效的使用场景：______
