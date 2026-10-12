from modules.policy.engine import risk_level


PROMPT_PATTERNS = [
    ("忽略之前", "试图覆盖原有系统规则"),
    ("忽略以上", "试图覆盖原有系统规则"),
    ("ignore previous", "英文提示注入指令"),
    ("ignore all previous", "英文提示注入指令"),
    ("system prompt", "伪造系统提示"),
    ("系统提示", "伪造系统提示"),
    ("你现在是系统", "伪造系统角色"),
    ("开发者指令", "伪造高优先级指令"),
    ("读取所有文件", "诱导越权文件读取"),
    ("导出密钥", "诱导敏感信息外传"),
    ("发送到外部地址", "诱导敏感信息外传"),
    ("上传到", "诱导数据外传"),
    ("绕过安全", "试图绕过安全策略"),
]

CONTEXT_POLLUTION_PATTERNS = [
    ("从现在开始", "试图污染后续上下文"),
    ("以后所有任务", "试图污染后续上下文"),
    ("永久记住", "试图写入长期记忆"),
    ("后续都必须", "试图改变后续行为"),
]


def scan_text(text: str):
    findings = []
    score = 0

    lower = text.lower()
    for keyword, desc in PROMPT_PATTERNS:
        if keyword.lower() in lower:
            score = max(score, 90)
            findings.append(
                {
                    "category": "prompt_injection",
                    "severity": "critical",
                    "title": "检测到提示注入指令",
                    "evidence": {"location": "content", "snippet": keyword, "description": desc},
                    "rule_id": "P-DOC-001",
                    "recommendation": "隔离该片段，禁止进入 LLM 上下文。",
                }
            )

    for keyword, desc in CONTEXT_POLLUTION_PATTERNS:
        if keyword.lower() in lower:
            score = max(score, 75)
            findings.append(
                {
                    "category": "context_pollution",
                    "severity": "high",
                    "title": "检测到上下文污染指令",
                    "evidence": {"location": "content", "snippet": keyword, "description": desc},
                    "rule_id": "P-DOC-002",
                    "recommendation": "降低该来源可信度，不允许影响后续任务规则。",
                }
            )

    return {"risk_score": score, "risk_level": risk_level(score), "findings": findings}
