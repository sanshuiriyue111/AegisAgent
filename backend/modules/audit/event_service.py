from core.database import dumps, get_conn, new_id, now_iso
from modules.audit.alert_service import create_alert
from modules.policy.engine import increment_policy_hits, match_event_policy


def build_attack_chain(project_id: str, task_id: str | None, current_event: dict) -> list[dict]:
    if not task_id:
        return [
            {
                "step": 1,
                "event_id": current_event["event_id"],
                "action": current_event["action"],
                "title": _event_title(current_event["action"], current_event["decision"]),
                "created_at": current_event["created_at"],
            }
        ]

    conn = get_conn()
    rows = conn.execute(
        """
        SELECT event_id, action, decision, created_at
        FROM security_events
        WHERE project_id=? AND task_id=?
        ORDER BY created_at ASC
        """,
        (project_id, task_id),
    ).fetchall()
    conn.close()
    chain = []
    for idx, row in enumerate(rows, start=1):
        item = dict(row)
        chain.append(
            {
                "step": idx,
                "event_id": item["event_id"],
                "action": item["action"],
                "title": _event_title(item["action"], item["decision"]),
                "created_at": item["created_at"],
            }
        )
    return chain


def _event_title(action: str, decision: str) -> str:
    titles = {
        "file.upload": "上传文件",
        "scan.run": "执行安全扫描",
        "document.parse": "解析文档上下文",
        "llm.call": "调用大模型",
        "file.read": "读取文件",
        "file.write": "写入文件",
        "api.request": "访问 API",
        "tool.call": "调用工具",
    }
    base = titles.get(action, action)
    if decision in ("deny", "isolate"):
        return f"{base}被阻断"
    if decision == "alert_only":
        return f"{base}触发告警"
    return base


def record_event(event: dict) -> dict:
    result = match_event_policy(event)
    event_id = new_id("evt")
    created_at = now_iso()
    project_id = event["project_id"]

    conn = get_conn()
    conn.execute(
        """
        INSERT INTO security_events
        (event_id, project_id, task_id, actor_type, actor_id, action, resource_type, resource_id,
         resource_path, risk_score, risk_level, decision, rule_ids_json, evidence_json, context_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            project_id,
            event.get("task_id"),
            event.get("actor_type"),
            event.get("actor_id"),
            event["action"],
            event.get("resource_type"),
            event.get("resource_id"),
            event.get("resource_path"),
            result["risk_score"],
            result["risk_level"],
            result["decision"],
            dumps(result["rule_ids"]),
            dumps(result["evidence"]),
            dumps(event.get("context", {})),
            created_at,
        ),
    )
    conn.commit()
    conn.close()

    increment_policy_hits(result["rule_ids"])
    alert_id = None
    if result["risk_score"] >= 40:
        attack_chain = build_attack_chain(
            project_id,
            event.get("task_id"),
            {
                "event_id": event_id,
                "action": event["action"],
                "decision": result["decision"],
                "created_at": created_at,
            },
        )
        alert_id = create_alert(
            project_id=project_id,
            event_id=event_id,
            category=result["category"],
            severity=result["risk_level"],
            decision=result["decision"],
            evidence=result["evidence"],
            matched_rules=result["matched_rules"],
            attack_chain=attack_chain,
        )

    return {
        "event_id": event_id,
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "decision": result["decision"],
        "matched_rules": result["rule_ids"],
        "alert_id": alert_id,
    }
