# 验证结果

本次整理日期：2026-10-12（Asia/Shanghai）。自动化功能验证使用 macOS、Python 3.13.2、FastAPI 0.115.0 和 SQLite。实际完成 7 组检查，全部通过；运行时间和详细结果见 [`verification.json`](evidence/verification.json)。

| 检查 | 结果 | 证据 |
| --- | --- | --- |
| 后端冒烟：项目、Markdown/DOCX 扫描、告警、模拟、评测与总览 | 通过 | [日志](evidence/smoke_test.txt) |
| 合法 PDF 文本提取与上传扫描 | 通过 | [日志](evidence/test_pdf_scan.txt) |
| 默认 API 时间窗口策略与告警 | 通过 | [日志](evidence/test_api_abuse.txt) |
| 演示数据重置及 7 个合成红队用例 | 通过 | [原始结果](evidence/demo-result.json) |
| 通过接口将阈值设为 3，连续请求决策为 allow、allow、alert_only | 通过 | [验证摘要](evidence/verification.json)、[告警响应](evidence/api-threshold-alert.json) |
| Markdown 评测报告导出 | 通过 | [导出报告](evidence/redteam-report.md) |
| 控制台 HTML、JS、CSS、Swagger 与 OpenAPI 可访问 | 通过 | [接口定义](evidence/openapi.json) |

## 浏览器验证

本次通过真实本地服务 `127.0.0.1:8765` 和 Codex 内置浏览器操作控制台，确认：

- 后端在线，演示项目总览已加载。
- 点击生成合成恶意样本，再点击上传并扫描，页面返回 critical 和命中证据。
- 点击扫描告警，页面展示证据、规则及上传—解析—扫描的三步时间线。
- 策略页显示启停、处置动作与等级控件。
- 点击运行全部红队用例，页面返回 7/7 处置匹配，5/7 阻断/隔离；对应截图保存在 [screenshots](screenshots/)。

## 如何复现

```bash
python scripts/verify.py
```

先按 README 安装依赖。验证脚本通过 `AEGIS_STORAGE_DIR` 使用独立临时目录，结束后清理测试数据库及上传文件。生成的 JSON 响应中，仅将本地目录替换为 `<temporary-storage>` 或 `<repository>`；业务字段及结果保持原值。测试输出、接口定义和源码 SHA256 一同保存。

## 结果的适用范围

这些检查验证具体功能链路，不是性能压测、独立安全评估或生产验收。7 个红队案例为人工构造的内置用例，没有正常样本集，不能据此推断真实场景的检出率或误报率。原型返回的 `false_positive_rate: 0.0` 是固定占位值；页面中的“检出率”实际按期望处置匹配计算。

PDF 专项测试已改用合法 PDF，并直接断言 pypdf 能提取目标文本，避免仅靠损坏 PDF 的字节回退命中规则而误判解析通过。
