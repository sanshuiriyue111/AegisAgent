import time
from pathlib import Path

from core.config import REDTEAM_CASES_DIR
from core.database import dumps, get_conn, loads, new_id, now_iso
from modules.audit.event_service import record_event
from modules.scanner.service import scan_file


def run_cases(project_id: str, case_ids: list[str]) -> dict:
    conn = get_conn()
    placeholders = ",".join("?" for _ in case_ids) if case_ids else ""
    if case_ids:
        cases = conn.execute(f"SELECT * FROM redteam_cases WHERE case_id IN ({placeholders}) AND enabled=1", case_ids).fetchall()
    else:
        cases = conn.execute("SELECT * FROM redteam_cases WHERE enabled=1").fetchall()
    conn.close()

    run_id = new_id("run")
    started = now_iso()
    results = []

    for row in cases:
        case = dict(row)
        start = time.time()
        actual_decision = "allow"
        alert_id = None

        if case["category"] in ("prompt_injection", "context_pollution", "malicious_url"):
            path = REDTEAM_CASES_DIR / case["sample_file"]
            scan_result = scan_file(str(path))
            if scan_result["findings"]:
                actual_decision = "isolate" if any(f.get("severity") in ("critical", "high") for f in scan_result["findings"]) else "alert_only"
                event = record_event(
                    {
                        "project_id": project_id,
                        "actor_type": "redteam",
                        "actor_id": "aegis_redlab",
                        "action": "document.parse",
                        "resource_type": "file",
                        "resource_path": str(path),
                        "context": {"findings": scan_result["findings"], "sample_text": Path(path).read_text(encoding="utf-8")},
                    }
                )
                alert_id = event.get("alert_id")

        elif case["category"] == "file_violation":
            event = record_event(
                {
                    "project_id": project_id,
                    "actor_type": "agent",
                    "actor_id": "redteam_agent",
                    "action": "file.read",
                    "resource_type": "file",
                    "resource_path": "/Users/demo/Desktop/secret.txt",
                    "context": {"tool_name": "read_file"},
                }
            )
            actual_decision = event["decision"]
            alert_id = event.get("alert_id")

        elif case["category"] == "api_abuse":
            actor_id = f"redteam_api_{run_id}"
            event = None
            for index in range(10):
                event = record_event(
                    {
                        "project_id": project_id,
                        "actor_type": "redteam",
                        "actor_id": actor_id,
                        "action": "api.request",
                        "resource_type": "api",
                        "resource_id": f"missing_file_{index}",
                        "resource_path": f"/api/v1/files/missing_file_{index}",
                        "context": {"status_code": 404, "method": "GET", "path": f"/api/v1/files/missing_file_{index}"},
                    }
                )
            actual_decision = event["decision"] if event else "allow"
            alert_id = event.get("alert_id") if event else None

        latency_ms = int((time.time() - start) * 1000)
        passed = actual_decision == case["expected_decision"]
        results.append(
            {
                "case_id": case["case_id"],
                "name": case["name"],
                "category": case["category"],
                "expected_decision": case["expected_decision"],
                "actual_decision": actual_decision,
                "passed": passed,
                "alert_id": alert_id,
                "latency_ms": latency_ms,
            }
        )

    total = len(results)
    passed_count = sum(1 for item in results if item["passed"])
    blocked = sum(1 for item in results if item["actual_decision"] in ("deny", "isolate"))
    avg_latency = int(sum(item["latency_ms"] for item in results) / total) if total else 0
    summary = {
        "total_cases": total,
        "passed": passed_count,
        "failed": total - passed_count,
        "detection_rate": passed_count / total if total else 0,
        "block_rate": blocked / total if total else 0,
        "false_positive_rate": 0.0,
        "avg_latency_ms": avg_latency,
    }

    conn = get_conn()
    now = now_iso()
    conn.execute(
        """
        INSERT INTO redteam_runs
        (run_id, project_id, status, summary_json, result_json, created_at, completed_at)
        VALUES (?, ?, 'completed', ?, ?, ?, ?)
        """,
        (run_id, project_id, dumps(summary), dumps({"summary": summary, "case_results": results}), started, now),
    )
    conn.commit()
    conn.close()

    return {"run_id": run_id, "status": "completed", "summary": summary}
