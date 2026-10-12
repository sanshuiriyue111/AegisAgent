from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from core.database import get_conn, loads, rows_to_dicts
from core.response import ok
from modules.redteam.runner import run_cases

router = APIRouter(tags=["redteam"])


class RedteamRunRequest(BaseModel):
    project_id: str
    case_ids: list[str] = []
    run_mode: str = "selected"


@router.get("/redteam/cases")
def list_cases(category: str | None = None):
    conn = get_conn()
    if category:
        rows = conn.execute("SELECT * FROM redteam_cases WHERE category=? ORDER BY case_id", (category,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM redteam_cases ORDER BY case_id").fetchall()
    conn.close()
    return ok({"items": rows_to_dicts(rows)})


@router.post("/redteam/runs")
def create_run(req: RedteamRunRequest):
    result = run_cases(req.project_id, [] if req.run_mode == "all" else req.case_ids)
    return ok({"run_id": result["run_id"], "status": result["status"], "summary": result["summary"]})


@router.get("/redteam/runs/{run_id}")
def get_run(run_id: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM redteam_runs WHERE run_id=?", (run_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="run not found")
    return ok({"run_id": run_id, "status": row["status"], "progress": 100, "summary": loads(row["summary_json"], {})})


@router.get("/redteam/runs/{run_id}/result")
def get_run_result(run_id: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM redteam_runs WHERE run_id=?", (run_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="run not found")
    result = loads(row["result_json"], {})
    result["run_id"] = run_id
    return ok(result)


@router.get("/redteam/runs/{run_id}/report.md", response_class=PlainTextResponse)
def export_run_report(run_id: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM redteam_runs WHERE run_id=?", (run_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="run not found")
    result = loads(row["result_json"], {})
    summary = result.get("summary", {})
    cases = result.get("case_results", [])
    lines = [
        "# AegisAgent 红队评测报告",
        "",
        f"- 运行编号：`{run_id}`",
        f"- 项目编号：`{row['project_id']}`",
        f"- 运行状态：`{row['status']}`",
        f"- 开始时间：{row['created_at']}",
        f"- 完成时间：{row['completed_at']}",
        "",
        "## 评测摘要",
        "",
        f"- 用例总数：{summary.get('total_cases', 0)}",
        f"- 通过用例：{summary.get('passed', 0)}",
        f"- 失败用例：{summary.get('failed', 0)}",
        f"- 检出率：{round(float(summary.get('detection_rate', 0)) * 100)}%",
        f"- 阻断/隔离率：{round(float(summary.get('block_rate', 0)) * 100)}%",
        f"- 平均检测耗时：{summary.get('avg_latency_ms', 0)}ms",
        "",
        "## 用例明细",
        "",
        "| 序号 | 用例 | 类型 | 期望动作 | 实际动作 | 结果 | 耗时 |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for idx, item in enumerate(cases, start=1):
        verdict = "通过" if item.get("passed") else "失败"
        lines.append(
            f"| {idx} | {item.get('name')} | {item.get('category')} | {item.get('expected_decision')} | {item.get('actual_decision')} | {verdict} | {item.get('latency_ms')}ms |"
        )
    lines.extend(
        [
            "",
            "## 结论",
            "",
            "本次评测覆盖提示注入、上下文污染、越权文件读取、API 参数遍历、敏感信息外传、伪系统提示覆盖和可疑外链投递等场景。系统能够对高危行为执行阻断或隔离，并对审计型风险生成告警记录。",
        ]
    )
    return "\n".join(lines)
