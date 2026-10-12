# 个人贡献与代码索引

杨乐乐已确认的个人负责范围：**文件扫描、策略检测、前后端联调**。

这是项目交付后的展示仓库，不包含历史开发提交。当前提交时间用于标识本次整理，不能作为原项目开发时间或各文件个人作者归属的证明。

| 负责内容 | 阅读入口 | 可验证内容 |
| --- | --- | --- |
| 文档解析与文件扫描 | [`service.py`](../backend/modules/scanner/service.py) | PDF 页文本、DOCX 段落及表格、文本文件提取；合并检测结果 |
| 提示注入与上下文检测 | [`prompt_injection.py`](../backend/modules/scanner/prompt_injection.py) | 规则关键词、风险等级、证据与建议 |
| 敏感信息及链接规则 | [`sensitive_data.py`](../backend/modules/scanner/sensitive_data.py)、[`malicious_url.py`](../backend/modules/scanner/malicious_url.py) | 正则匹配与链接启发式检测 |
| 事件策略匹配 | [`engine.py`](../backend/modules/policy/engine.py) | 路径、上下文、API 窗口与阈值；返回规则及处置决策 |
| 默认策略与接口联调 | [`default_policies.py`](../backend/modules/policy/default_policies.py)、[`policies.py`](../backend/api/policies.py) | 策略参数、启停、等级、处置动作和配置更新 |
| 上传/扫描/告警联调 | [`files.py`](../backend/api/files.py)、[`scans.py`](../backend/api/scans.py)、[`app.js`](../frontend/app.js) | multipart 上传、scan_task_id、风险结果、告警证据与控制台请求链 |

接口、前端与存储文件列为联调阅读入口，不意味着个人独立设计或实现其中全部代码。数据库、项目管理、审计、模拟器和评测模块作为完整运行所需的配套代码保留。

## 面试可演示的三条链路

1. **文件扫描**：在安全工作台生成合成样本 → 上传并扫描 → 查看风险等级、规则和证据。
2. **策略检测**：查看 `P-API-001` 的阈值配置 → 上报窗口内连续异常请求 → 查看 `api_abuse` 告警。验证脚本包含阈值为 3 时的 `allow → allow → alert_only` 检查。
3. **联调闭环**：从浏览器 Fetch 请求追踪上传返回值 → 扫描结果接口 → 告警列表/详情；展示任务 ID 与证据关联。

## 本次整理的变更

- 从现有项目复制必要源码，未复制数据库、上传记录、虚拟环境、竞赛个人材料和重复压缩包。
- 增加 README、贡献说明、演示截图、接口说明与真实验证结果。
- 增加 `AEGIS_STORAGE_DIR` 环境配置，允许独立运行和临时测试数据目录。
- 增加可移植的启动与验证脚本；保留原项目功能测试，并将 PDF 测试样本修为合法 PDF，以验证真实文本解析路径。
- 不回填历史提交，不将本次整理产生的证据误称为过去的开发日志。
