from datetime import datetime, timedelta, timezone

from core.database import get_conn, loads


def risk_level(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def load_enabled_policies():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM policies WHERE enabled=1").fetchall()
    conn.close()
    policies = []
    for row in rows:
        item = dict(row)
        item["config"] = loads(item.pop("config_json"), {})
        policies.append(item)
    return policies


def match_event_policy(event: dict) -> dict:
    matched = []
    risk_score = 0
    decision = "allow"
    category = "unknown"
    evidence = []

    policies = load_enabled_policies()
    action = event.get("action", "")
    path = event.get("resource_path") or ""
    context_text = str(event.get("context") or "")

    for policy in policies:
        if policy["policy_id"] == "P-FILE-001" and action in ("file.read", "file.write", "file.export"):
            blocked = policy["config"].get("blocked_path_keywords", [])
            hit = [kw for kw in blocked if kw.lower() in path.lower()]
            if hit:
                matched.append(policy)
                risk_score = max(risk_score, 95)
                decision = policy["decision"]
                category = policy["category"]
                evidence.append({"type": "path", "value": path, "description": f"路径命中高危关键词: {', '.join(hit)}"})

        if policy["policy_id"] == "P-DOC-001" and action in ("document.parse", "llm.call", "scan.run"):
            keywords = policy["config"].get("keywords", [])
            hit = [kw for kw in keywords if kw.lower() in context_text.lower()]
            if hit:
                matched.append(policy)
                risk_score = max(risk_score, 90)
                decision = policy["decision"]
                category = policy["category"]
                evidence.append({"type": "text", "value": hit[:5], "description": "上下文命中文档提示注入关键词"})

        if policy["policy_id"] == "P-API-001" and action == "api.request":
            context = event.get("context") or {}
            status_code = int(context.get("status_code") or 0)
            abuse_signal = bool(context.get("abuse_signal"))
            if status_code in (401, 403, 404) or abuse_signal:
                threshold = int(policy["config"].get("threshold", 10))
                window_seconds = int(policy["config"].get("window_seconds", 60))
                cutoff = (datetime.now(timezone.utc).astimezone() - timedelta(seconds=window_seconds)).isoformat(timespec="seconds")
                conn = get_conn()
                recent_count = conn.execute(
                    """
                    SELECT COUNT(*) AS c
                    FROM security_events
                    WHERE project_id=?
                      AND actor_id=?
                      AND action='api.request'
                      AND created_at>=?
                    """,
                    (event.get("project_id"), event.get("actor_id"), cutoff),
                ).fetchone()["c"]
                conn.close()
                if recent_count + 1 >= threshold:
                    matched.append(policy)
                    risk_score = max(risk_score, 75)
                    decision = policy["decision"]
                    category = policy["category"]
                    evidence.append(
                        {
                            "type": "api_sequence",
                            "value": {"actor_id": event.get("actor_id"), "count": recent_count + 1, "window_seconds": window_seconds},
                            "description": "短时间内异常 API 请求次数超过阈值",
                        }
                    )

    return {
        "risk_score": risk_score,
        "risk_level": risk_level(risk_score),
        "decision": decision,
        "category": category,
        "matched_rules": [{"rule_id": p["policy_id"], "name": p["name"]} for p in matched],
        "rule_ids": [p["policy_id"] for p in matched],
        "evidence": evidence,
    }


def increment_policy_hits(rule_ids):
    if not rule_ids:
        return
    conn = get_conn()
    for rule_id in rule_ids:
        conn.execute("UPDATE policies SET hit_count=hit_count+1 WHERE policy_id=?", (rule_id,))
    conn.commit()
    conn.close()
