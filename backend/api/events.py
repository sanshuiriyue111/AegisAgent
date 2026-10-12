from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from core.database import get_conn, loads, row_to_dict, rows_to_dicts
from core.response import ok, paginate
from modules.audit.event_service import record_event

router = APIRouter(tags=["events"])


class EventCreateRequest(BaseModel):
    project_id: str
    task_id: str | None = None
    actor_type: str = "agent"
    actor_id: str = "agent_demo"
    action: str
    resource_type: str | None = None
    resource_id: str | None = None
    resource_path: str | None = None
    context: dict = {}


@router.post("/events")
def create_event(req: EventCreateRequest):
    return ok(record_event(req.model_dump()))


@router.get("/events")
def list_events(
    project_id: str,
    action: str | None = None,
    risk_level: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
):
    offset = (page - 1) * page_size
    where = "WHERE project_id=?"
    params = [project_id]
    if action:
        where += " AND action=?"
        params.append(action)
    if risk_level:
        where += " AND risk_level=?"
        params.append(risk_level)
    conn = get_conn()
    total = conn.execute(f"SELECT COUNT(*) AS c FROM security_events {where}", params).fetchone()["c"]
    rows = conn.execute(f"SELECT * FROM security_events {where} ORDER BY created_at DESC LIMIT ? OFFSET ?", (*params, page_size, offset)).fetchall()
    conn.close()
    items = rows_to_dicts(rows)
    for item in items:
        item["rule_ids"] = loads(item.pop("rule_ids_json"), [])
        item["evidence"] = loads(item.pop("evidence_json"), [])
        item["context"] = loads(item.pop("context_json"), {})
    return ok(paginate(items, page, page_size, total))


@router.get("/events/{event_id}")
def get_event(event_id: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM security_events WHERE event_id=?", (event_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="event not found")
    item = row_to_dict(row)
    item["rule_ids"] = loads(item.pop("rule_ids_json"), [])
    item["evidence"] = loads(item.pop("evidence_json"), [])
    item["context"] = loads(item.pop("context_json"), {})
    return ok(item)

