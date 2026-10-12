from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.database import dumps, get_conn, loads, now_iso, row_to_dict, rows_to_dicts
from core.response import ok

router = APIRouter(tags=["policies"])


class PolicyUpdateRequest(BaseModel):
    enabled: bool | None = None
    severity: str | None = None
    decision: str | None = None
    config: dict | None = None


def _policy_row(row):
    item = row_to_dict(row)
    item["enabled"] = bool(item["enabled"])
    item["config"] = loads(item.pop("config_json"), {})
    return item


@router.get("/policies")
def list_policies(category: str | None = None):
    conn = get_conn()
    if category:
        rows = conn.execute("SELECT * FROM policies WHERE category=? ORDER BY policy_id", (category,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM policies ORDER BY policy_id").fetchall()
    conn.close()
    return ok({"items": [_policy_row(row) for row in rows]})


@router.get("/policies/{policy_id}")
def get_policy(policy_id: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM policies WHERE policy_id=?", (policy_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="policy not found")
    return ok(_policy_row(row))


@router.put("/policies/{policy_id}")
def update_policy(policy_id: str, req: PolicyUpdateRequest):
    conn = get_conn()
    row = conn.execute("SELECT * FROM policies WHERE policy_id=?", (policy_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="policy not found")
    current = _policy_row(row)
    enabled = current["enabled"] if req.enabled is None else req.enabled
    severity = current["severity"] if req.severity is None else req.severity
    decision = current["decision"] if req.decision is None else req.decision
    config = current["config"] if req.config is None else req.config
    now = now_iso()
    conn.execute(
        "UPDATE policies SET enabled=?, severity=?, decision=?, config_json=?, updated_at=? WHERE policy_id=?",
        (1 if enabled else 0, severity, decision, dumps(config), now, policy_id),
    )
    conn.commit()
    conn.close()
    return ok({"policy_id": policy_id, "enabled": enabled, "updated_at": now}, message="策略已更新")

