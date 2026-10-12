from core.database import dumps, get_conn, new_id, now_iso


def create_alert(
    project_id: str,
    event_id: str | None,
    category: str,
    severity: str,
    decision: str,
    evidence,
    matched_rules,
    attack_chain=None,
):
    title_map = {
        "prompt_injection": "检测到文档提示注入攻击",
        "context_pollution": "检测到上下文污染风险",
        "file_violation": "检测到越权文件访问",
        "api_abuse": "检测到 API 滥用风险",
        "sensitive_leak": "检测到敏感信息泄露风险",
        "malicious_url": "检测到可疑外链",
    }
    recommendation_map = {
        "prompt_injection": "隔离高风险文档片段，禁止进入 LLM 上下文。",
        "context_pollution": "降低该来源可信度，避免影响后续任务行为。",
        "file_violation": "限制工具访问路径，仅允许访问项目授权目录。",
        "api_abuse": "限制请求频率并检查对象级授权。",
        "sensitive_leak": "输出前进行脱敏或要求用户确认。",
        "malicious_url": "人工确认外链来源，必要时阻断访问。",
    }
    alert_id = new_id("alert")
    now = now_iso()
    title = title_map.get(category, "检测到安全风险")
    recommendation = recommendation_map.get(category, "请人工确认并调整策略。")
    description = f"安全策略检测到 {category} 风险，处置动作为 {decision}。"

    conn = get_conn()
    conn.execute(
        """
        INSERT INTO alerts
        (alert_id, project_id, event_id, title, category, severity, status, decision, description,
         recommendation, evidence_json, attack_chain_json, matched_rules_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert_id,
            project_id,
            event_id,
            title,
            category,
            severity,
            decision,
            description,
            recommendation,
            dumps(evidence or []),
            dumps(attack_chain or []),
            dumps(matched_rules or []),
            now,
            now,
        ),
    )
    conn.commit()
    conn.close()
    return alert_id
