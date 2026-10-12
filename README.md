# AegisAgent 智盾

基于 **Python / FastAPI / SQLite** 的智能体安全审计原型，提供文档规则扫描、事件策略匹配、证据告警和前后端控制台。

本仓库用于展示项目实现与可复现的功能验证。**杨乐乐负责文件扫描、策略检测与前后端联调**；仓库包含用于运行完整演示的配套模块，不代表全部模块均由本人独立完成。

## 界面预览

截图来自本仓库在本地运行后的真实页面，输入为人工构造的演示样本。

| 文件扫描 | 告警与证据 |
| --- | --- |
| ![文件扫描](docs/screenshots/02-document-scan.jpg) | ![告警与证据](docs/screenshots/03-alert-evidence.jpg) |
| 风险总览 | 策略配置 |
| ![风险总览](docs/screenshots/01-dashboard.jpg) | ![策略配置](docs/screenshots/04-policies.jpg) |

[更多界面与演示步骤](docs/DEMO.md) · [个人贡献与代码索引](docs/CONTRIBUTIONS.md) · [验证结果](docs/VERIFICATION.md)

## 主要功能

- **文档扫描**：PDF、DOCX、Markdown/TXT 文本提取；提示注入、上下文污染、敏感信息与可疑链接规则检测。
- **策略检测**：按文件路径关键词、上下文关键词、API 请求时间窗口匹配规则，返回风险等级、处置动作和证据。
- **审计联调**：上传、解析、扫描与告警数据衔接，展示证据和按任务关联的事件时间线。
- **配套演示**：项目管理、可配置策略、模拟工具调用、7 个内置红队用例及 Markdown 报告导出。

## 快速运行

需要 Python 3.10 或以上；本次验证使用 Python 3.13。前端为静态 HTML/CSS/JavaScript，无需 npm 构建，也不需要模型 API 密钥。

```bash
python3 -m venv .venv
```

macOS / Linux：

```bash
source .venv/bin/activate
```

Windows PowerShell：

```powershell
.\.venv\Scripts\Activate.ps1
```

安装依赖并启动（在仓库根目录执行）：

```bash
python -m pip install -r backend/requirements.txt
python scripts/start_demo.py --seed
```

打开 [本地控制台](http://127.0.0.1:8000/console/) 或 [接口文档](http://127.0.0.1:8000/docs)。`--seed` 会重置演示项目及默认策略，普通启动可省略。端口可通过 `--port 8765` 调整。默认数据保存在 `backend/storage/`，不纳入 Git；可通过环境变量 `AEGIS_STORAGE_DIR` 指定独立目录。

## 验证与证据

```bash
python scripts/verify.py
```

验证在临时目录执行，生成 `docs/evidence/verification.json`、测试日志、OpenAPI 与演示响应。详见 [验证说明](docs/VERIFICATION.md)。截图中的内置样本结果只用于回归演示，不代表真实攻击检出率。

## 结构

```text
backend/
  api/                 REST 接口与参数模型
  core/                配置、SQLite、响应封装
  modules/scanner/     文档提取与规则扫描
  modules/policy/      事件规则与时间窗口检测
  modules/audit/       事件记录及告警证据
  modules/redteam/     合成用例与评测
  modules/demo/        演示数据生成
  scripts/             原项目功能测试脚本
frontend/              静态控制台与 Fetch 联调
scripts/               可移植启动与验证入口
docs/                  代码索引、截图、演示和验证结果
```

## 当前边界

这是本地 MVP：没有登录、角色/租户鉴权和生产部署验证；文件解析和评测同步执行；PDF 依赖可提取文本，未接入 OCR；智能体工具调用为模拟，未对接真实 LLM 或系统文件读取工具。`deny/isolate` 是原型记录的决策，不代表已实现生产环境的隔离执行。

API 时间窗口策略当前统计同一项目/主体在窗口内的全部已记录 `api.request`，并在当前请求带异常状态或信号时判断阈值，不等同于网关限流。原评测字段 `detection_rate` 计算的是期望处置匹配比例；`false_positive_rate` 是固定占位值，没有正常样本集支持，不作为测量结果。其他实现边界见 [代码说明](docs/ARCHITECTURE.md)。
