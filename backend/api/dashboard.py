from fastapi import APIRouter

from core.database import get_conn, loads, rows_to_dicts
from core.response import ok

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard/overview")
def overview(project_id: str):
    conn = get_conn()
    row = conn.execute(
        """
        SELECT
          COUNT(*) AS total_alerts,
          SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) AS critical_alerts,
          SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) AS high_alerts,
          SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) AS open_alerts
        FROM alerts WHERE project_id=?
        """,
        (project_id,),
    ).fetchone()
    blocked = conn.execute(
        "SELECT COUNT(*) AS c FROM security_events WHERE project_id=? AND decision IN ('deny','isolate')",
        (project_id,),
    ).fetchone()["c"]
    files = conn.execute("SELECT COUNT(*) AS c FROM files WHERE project_id=?", (project_id,)).fetchone()["c"]
    max_score = conn.execute("SELECT COALESCE(MAX(risk_score), 0) AS s FROM security_events WHERE project_id=?", (project_id,)).fetchone()["s"]
    latest_run = conn.execute(
        "SELECT summary_json FROM redteam_runs WHERE project_id=? ORDER BY created_at DESC LIMIT 1",
        (project_id,),
    ).fetchone()
    conn.close()
    redteam_summary = loads(latest_run["summary_json"], {}) if latest_run else {}
    score = int(max_score or 0)
    level = "critical" if score >= 90 else "high" if score >= 70 else "medium" if score >= 40 else "info"
    return ok(
        {
            "risk_score": score,
            "risk_level": level,
            "total_alerts": row["total_alerts"] or 0,
            "critical_alerts": row["critical_alerts"] or 0,
            "high_alerts": row["high_alerts"] or 0,
            "blocked_actions": blocked,
            "open_alerts": row["open_alerts"] or 0,
            "scanned_files": files,
            "redteam_detection_rate": redteam_summary.get("detection_rate", 0),
        }
    )


@router.get("/dashboard/alert-trend")
def alert_trend(project_id: str, range: str = "7d"):
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT substr(created_at, 1, 10) AS date,
          SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) AS critical,
          SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) AS high,
          SUM(CASE WHEN severity='medium' THEN 1 ELSE 0 END) AS medium,
          SUM(CASE WHEN severity='low' THEN 1 ELSE 0 END) AS low
        FROM alerts
        WHERE project_id=?
        GROUP BY substr(created_at, 1, 10)
        ORDER BY date
        """,
        (project_id,),
    ).fetchall()
    conn.close()
    return ok({"items": rows_to_dicts(rows)})


@router.get("/dashboard/category-distribution")
def category_distribution(project_id: str):
    conn = get_conn()
    rows = conn.execute(
        "SELECT category, COUNT(*) AS count FROM alerts WHERE project_id=? GROUP BY category ORDER BY count DESC",
        (project_id,),
    ).fetchall()
    conn.close()
    return ok({"items": rows_to_dicts(rows)})
