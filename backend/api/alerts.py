from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from core.database import get_conn, loads, now_iso, row_to_dict, rows_to_dicts
from core.response import ok, paginate

router = APIRouter(tags=["alerts"])


class AlertUpdateRequest(BaseModel):
    status: str
    comment: str | None = None


@router.get("/alerts")
def list_alerts(
    project_id: str,
    severity: str | None = None,
    status: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
):
    offset = (page - 1) * page_size
    where = "WHERE project_id=?"
    params = [project_id]
    if severity:
        where += " AND severity=?"
        params.append(severity)
    if status:
        where += " AND status=?"
        params.append(status)
    conn = get_conn()
    total = conn.execute(f"SELECT COUNT(*) AS c FROM alerts {where}", params).fetchone()["c"]
    rows = conn.execute(f"SELECT * FROM alerts {where} ORDER BY created_at DESC LIMIT ? OFFSET ?", (*params, page_size, offset)).fetchall()
    conn.close()
    items = rows_to_dicts(rows)
    for item in items:
        item["evidence"] = loads(item.pop("evidence_json"), [])
        item["attack_chain"] = loads(item.pop("attack_chain_json"), [])
        item["matched_rules"] = loads(item.pop("matched_rules_json"), [])
    return ok(paginate(items, page, page_size, total))


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM alerts WHERE alert_id=?", (alert_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="alert not found")
    item = row_to_dict(row)
    item["evidence"] = loads(item.pop("evidence_json"), [])
    item["attack_chain"] = loads(item.pop("attack_chain_json"), [])
    item["matched_rules"] = loads(item.pop("matched_rules_json"), [])
    return ok(item)


@router.patch("/alerts/{alert_id}")
def update_alert(alert_id: str, req: AlertUpdateRequest):
    conn = get_conn()
    row = conn.execute("SELECT alert_id FROM alerts WHERE alert_id=?", (alert_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="alert not found")
    conn.execute("UPDATE alerts SET status=?, updated_at=? WHERE alert_id=?", (req.status, now_iso(), alert_id))
    conn.commit()
    conn.close()
    return ok({"alert_id": alert_id, "status": req.status}, message="告警状态已更新")
