import re


URL_PATTERN = re.compile(r"https?://[^\s)>\"]+")
SUSPICIOUS_WORDS = ["token=", "apikey=", "redirect=", "download", "pastebin", "raw.githubusercontent"]


def scan_urls(text: str):
    findings = []
    for url in URL_PATTERN.findall(text):
        if any(word in url.lower() for word in SUSPICIOUS_WORDS):
            findings.append(
                {
                    "category": "malicious_url",
                    "severity": "medium",
                    "title": "检测到可疑外链",
                    "evidence": {"location": "content", "snippet": url, "description": "URL 含敏感参数或可疑下载特征"},
                    "rule_id": "P-URL-001",
                    "recommendation": "人工确认外链来源，必要时阻断访问。",
                }
            )
    return findings

