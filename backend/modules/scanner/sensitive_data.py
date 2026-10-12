import re


PATTERNS = [
    ("api_key", re.compile(r"(?i)(api[_-]?key|token|secret)\s*[:=]\s*[A-Za-z0-9_\-]{12,}")),
    ("phone", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
]


def scan_sensitive_data(text: str):
    findings = []
    for name, pattern in PATTERNS:
        match = pattern.search(text)
        if match:
            findings.append(
                {
                    "category": "sensitive_leak",
                    "severity": "medium",
                    "title": "检测到疑似敏感信息",
                    "evidence": {"location": "content", "snippet": match.group(0)[:80], "description": name},
                    "rule_id": "P-OUT-001",
                    "recommendation": "导出或发送前进行脱敏处理。",
                }
            )
    return findings

