import hashlib
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse

from core.config import FILES_DIR
from core.database import dumps, get_conn, new_id, now_iso, row_to_dict, rows_to_dicts
from core.response import ok, paginate
from modules.scanner.service import scan_file

router = APIRouter(tags=["files"])


def _ensure_project(project_id: str):
    conn = get_conn()
    row = conn.execute("SELECT project_id FROM projects WHERE project_id=?", (project_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="project not found")


@router.post("/projects/{project_id}/files")
async def upload_file(project_id: str, file: UploadFile = File(...), file_role: str = Form("source"), auto_scan: bool = Form(True)):
    _ensure_project(project_id)
    data = await file.read()
    file_id = new_id("file")
    file_name = file.filename or f"{file_id}.txt"
    file_type = Path(file_name).suffix.lstrip(".").lower() or "txt"
    project_dir = FILES_DIR / project_id
    project_dir.mkdir(parents=True, exist_ok=True)
    storage_path = project_dir / f"{file_id}_{file_name}"
    storage_path.write_bytes(data)
    sha256 = hashlib.sha256(data).hexdigest()
    now = now_iso()

    scan_status = "pending" if auto_scan else "not_started"
    risk_score = 0
    risk_level = "info"
    scan_task_id = None

    conn = get_conn()
    conn.execute(
        """
        INSERT INTO files
        (file_id, project_id, file_name, file_type, file_size, sha256, storage_path, risk_score, risk_level, scan_status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (file_id, project_id, file_name, file_type, len(data), sha256, str(storage_path), risk_score, risk_level, scan_status, now),
    )

    if auto_scan:
        scan_task_id = new_id("task_scan")
        conn.execute(
            """
            INSERT INTO security_events
            (event_id, project_id, task_id, actor_type, actor_id, action, resource_type, resource_id,
             resource_path, risk_score, risk_level, decision, rule_ids_json, evidence_json, context_json, created_at)
            VALUES (?, ?, ?, 'user', 'demo_user', 'file.upload', 'file', ?, ?, 0, 'info', 'allow', ?, ?, ?, ?)
            """,
            (
                new_id("evt"),
                project_id,
                scan_task_id,
                file_id,
                str(storage_path),
                dumps([]),
                dumps([]),
                dumps({"file_name": file_name, "file_type": file_type, "file_size": len(data)}),
                now,
            ),
        )
        conn.execute(
            """
            INSERT INTO security_events
            (event_id, project_id, task_id, actor_type, actor_id, action, resource_type, resource_id,
             resource_path, risk_score, risk_level, decision, rule_ids_json, evidence_json, context_json, created_at)
            VALUES (?, ?, ?, 'system', 'parser', 'document.parse', 'file', ?, ?, 0, 'info', 'allow', ?, ?, ?, ?)
            """,
            (
                new_id("evt"),
                project_id,
                scan_task_id,
                file_id,
                str(storage_path),
                dumps([]),
                dumps([]),
                dumps({"file_name": file_name, "parser": "aegis_text_extractor"}),
                now,
            ),
        )
        result = scan_file(str(storage_path))
        risk_score = result["risk_score"]
        risk_level = result["risk_level"]
        conn.execute(
            """
            INSERT INTO scan_tasks
            (task_id, project_id, target_type, target_id, status, progress, result_json, created_at, completed_at)
            VALUES (?, ?, 'file', ?, 'completed', 100, ?, ?, ?)
            """,
            (scan_task_id, project_id, file_id, __import__("json").dumps(result, ensure_ascii=False), now, now),
        )
        conn.execute(
            "UPDATE files SET risk_score=?, risk_level=?, scan_status='completed' WHERE file_id=?",
            (risk_score, risk_level, file_id),
        )
        # Create events/alerts from findings lazily via scan route style.
        from api.scans import create_alerts_for_scan

        create_alerts_for_scan(conn, project_id, scan_task_id, file_id, str(storage_path), result)

    conn.commit()
    conn.close()
    return ok(
        {
            "file_id": file_id,
            "project_id": project_id,
            "file_name": file_name,
            "file_type": file_type,
            "file_size": len(data),
            "sha256": sha256,
            "scan_task_id": scan_task_id,
            "scan_status": "completed" if auto_scan else "not_started",
            "risk_score": risk_score,
            "risk_level": risk_level,
        }
    )


@router.get("/projects/{project_id}/files")
def list_files(project_id: str, scan_status: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100)):
    _ensure_project(project_id)
    offset = (page - 1) * page_size
    where = "WHERE project_id=?"
    params = [project_id]
    if scan_status:
        where += " AND scan_status=?"
        params.append(scan_status)
    conn = get_conn()
    total = conn.execute(f"SELECT COUNT(*) AS c FROM files {where}", params).fetchone()["c"]
    rows = conn.execute(f"SELECT * FROM files {where} ORDER BY created_at DESC LIMIT ? OFFSET ?", (*params, page_size, offset)).fetchall()
    conn.close()
    return ok(paginate(rows_to_dicts(rows), page, page_size, total))


@router.get("/files/{file_id}")
def get_file(file_id: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM files WHERE file_id=?", (file_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="file not found")
    return ok(row_to_dict(row))


@router.delete("/files/{file_id}")
def delete_file(file_id: str):
    conn = get_conn()
    row = conn.execute("SELECT storage_path FROM files WHERE file_id=?", (file_id,)).fetchone()
    if row:
        Path(row["storage_path"]).unlink(missing_ok=True)
    conn.execute("DELETE FROM files WHERE file_id=?", (file_id,))
    conn.commit()
    conn.close()
    return ok(message="文件已删除")


@router.get("/files/{file_id}/download")
def download_file(file_id: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM files WHERE file_id=?", (file_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="file not found")
    return FileResponse(row["storage_path"], filename=row["file_name"])
