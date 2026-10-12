import json

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.database import dumps, get_conn, loads, new_id, now_iso, row_to_dict
from core.response import ok
from modules.scanner.service import scan_file

router = APIRouter(tags=["scans"])


class ScanCreateRequest(BaseModel):
    project_id: str
    target_type: str = "file"
    target_id: str
    scan_types: list[str] = ["prompt_injection", "sensitive_data", "malicious_url"]


def create_alerts_for_scan(conn, project_id: str, task_id: str, file_id: str, path: str, result: dict):
    for finding in result.get("findings", []):
        event_id = new_id("evt")
        now = now_iso()
        rule_id = finding.get("rule_id")
        evidence = [finding.get("evidence", {})]
        conn.execute(
            """
            INSERT INTO security_events
            (event_id, project_id, task_id, actor_type, actor_id, action, resource_type, resource_id,
             resource_path, risk_score, risk_level, decision, rule_ids_json, evidence_json, context_json, created_at)
            VALUES (?, ?, ?, 'system', 'scanner', 'scan.run', 'file', ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                project_id,
                task_id,
                file_id,
                path,
                result.get("risk_score", 0),
                finding.get("severity", result.get("risk_level", "info")),
                "isolate" if finding.get("severity") in ("critical", "high") else "alert_only",
                dumps([rule_id] if rule_id else []),
                dumps(evidence),
                dumps({"finding": finding}),
                now,
            ),
        )
        if rule_id:
            conn.execute("UPDATE policies SET hit_count=hit_count+1 WHERE policy_id=?", (rule_id,))
        # create_alert opens its own connection, so inline insert to share transaction.
        alert_id = new_id("alert")
        attack_chain = _build_scan_attack_chain(conn, project_id, task_id)
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
                finding.get("title", "检测到安全风险"),
                finding.get("category", "unknown"),
                finding.get("severity", "medium"),
                "isolate" if finding.get("severity") in ("critical", "high") else "alert_only",
                finding.get("title", "检测到安全风险"),
                finding.get("recommendation", "请人工确认。"),
                dumps(evidence),
                dumps(attack_chain),
                dumps([{"rule_id": rule_id, "name": rule_id}] if rule_id else []),
                now,
                now,
            ),
        )


@router.post("/scans")
def create_scan(req: ScanCreateRequest):
    if req.target_type != "file":
        raise HTTPException(status_code=400, detail="only file scan is supported in MVP")
    conn = get_conn()
    file_row = conn.execute("SELECT * FROM files WHERE file_id=? AND project_id=?", (req.target_id, req.project_id)).fetchone()
    if not file_row:
        conn.close()
        raise HTTPException(status_code=404, detail="file not found")
    task_id = new_id("task_scan")
    now = now_iso()
    conn.execute(
        """
        INSERT INTO security_events
        (event_id, project_id, task_id, actor_type, actor_id, action, resource_type, resource_id,
         resource_path, risk_score, risk_level, decision, rule_ids_json, evidence_json, context_json, created_at)
        VALUES (?, ?, ?, 'system', 'parser', 'document.parse', 'file', ?, ?, 0, 'info', 'allow', ?, ?, ?, ?)
        """,
        (
            new_id("evt"),
            req.project_id,
            task_id,
            req.target_id,
            file_row["storage_path"],
            dumps([]),
            dumps([]),
            dumps({"parser": "aegis_text_extractor", "manual_scan": True}),
            now,
        ),
    )
    result = scan_file(file_row["storage_path"])
    conn.execute(
        """
        INSERT INTO scan_tasks
        (task_id, project_id, target_type, target_id, status, progress, result_json, created_at, completed_at)
        VALUES (?, ?, ?, ?, 'completed', 100, ?, ?, ?)
        """,
        (task_id, req.project_id, req.target_type, req.target_id, json.dumps(result, ensure_ascii=False), now, now),
    )
    conn.execute(
        "UPDATE files SET risk_score=?, risk_level=?, scan_status='completed' WHERE file_id=?",
        (result["risk_score"], result["risk_level"], req.target_id),
    )
    create_alerts_for_scan(conn, req.project_id, task_id, req.target_id, file_row["storage_path"], result)
    conn.commit()
    conn.close()
    return ok({"task_id": task_id, "status": "completed", "created_at": now})


def _build_scan_attack_chain(conn, project_id: str, task_id: str) -> list[dict]:
    rows = conn.execute(
        """
        SELECT event_id, action, decision, created_at
        FROM security_events
        WHERE project_id=? AND task_id=?
        ORDER BY created_at ASC, rowid ASC
        """,
        (project_id, task_id),
    ).fetchall()
    chain = []
    for idx, row in enumerate(rows, start=1):
        action = row["action"]
        decision = row["decision"]
        chain.append(
            {
                "step": idx,
                "event_id": row["event_id"],
                "action": action,
                "title": _scan_chain_title(action, decision),
                "created_at": row["created_at"],
            }
        )
    return chain


def _scan_chain_title(action: str, decision: str) -> str:
    titles = {
        "file.upload": "用户上传待检测文件",
        "document.parse": "系统解析文档并抽取文本",
        "scan.run": "扫描引擎命中风险规则",
    }
    title = titles.get(action, action)
    if decision in ("deny", "isolate"):
        return f"{title}，执行阻断/隔离"
    if decision == "alert_only":
        return f"{title}，生成告警"
    return title


@router.get("/scans/{task_id}")
def get_scan(task_id: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM scan_tasks WHERE task_id=?", (task_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="scan not found")
    data = row_to_dict(row)
    data["result"] = loads(data.pop("result_json"), {})
    return ok(data)


@router.get("/scans/{task_id}/result")
def get_scan_result(task_id: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM scan_tasks WHERE task_id=?", (task_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="scan not found")
    result = loads(row["result_json"], {})
    return ok(
        {
            "task_id": task_id,
            "target_type": row["target_type"],
            "target_id": row["target_id"],
            "risk_score": result.get("risk_score", 0),
            "risk_level": result.get("risk_level", "info"),
            "findings": result.get("findings", []),
        }
    )
