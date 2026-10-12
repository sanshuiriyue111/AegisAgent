from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from core.database import get_conn, new_id, now_iso, row_to_dict, rows_to_dicts
from core.response import ok, paginate

router = APIRouter(tags=["projects"])


class ProjectCreateRequest(BaseModel):
    name: str
    description: str = ""


@router.post("/projects")
def create_project(req: ProjectCreateRequest):
    project_id = new_id("proj")
    now = now_iso()
    conn = get_conn()
    conn.execute(
        "INSERT INTO projects (project_id, name, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (project_id, req.name, req.description, now, now),
    )
    conn.commit()
    conn.close()
    return ok({"project_id": project_id, "name": req.name, "description": req.description, "created_at": now})


@router.get("/projects")
def list_projects(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100)):
    offset = (page - 1) * page_size
    conn = get_conn()
    total = conn.execute("SELECT COUNT(*) AS c FROM projects").fetchone()["c"]
    rows = conn.execute(
        """
        SELECT p.*,
          (SELECT COUNT(*) FROM alerts a WHERE a.project_id=p.project_id) AS alert_count,
          (SELECT COUNT(*) FROM alerts a WHERE a.project_id=p.project_id AND a.severity='critical') AS critical_count
        FROM projects p
        ORDER BY p.created_at DESC
        LIMIT ? OFFSET ?
        """,
        (page_size, offset),
    ).fetchall()
    conn.close()
    return ok(paginate(rows_to_dicts(rows), page, page_size, total))


@router.get("/projects/{project_id}")
def get_project(project_id: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM projects WHERE project_id=?", (project_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="project not found")
    return ok(row_to_dict(row))


@router.delete("/projects/{project_id}")
def delete_project(project_id: str):
    conn = get_conn()
    conn.execute("DELETE FROM projects WHERE project_id=?", (project_id,))
    conn.execute("DELETE FROM files WHERE project_id=?", (project_id,))
    conn.execute("DELETE FROM scan_tasks WHERE project_id=?", (project_id,))
    conn.execute("DELETE FROM security_events WHERE project_id=?", (project_id,))
    conn.execute("DELETE FROM alerts WHERE project_id=?", (project_id,))
    conn.execute("DELETE FROM redteam_runs WHERE project_id=?", (project_id,))
    conn.commit()
    conn.close()
    return ok(message="项目已删除")

