from fastapi import APIRouter
from pydantic import BaseModel

from core.database import new_id
from core.response import ok
from modules.audit.event_service import record_event

router = APIRouter(tags=["agent-simulator"])


class AgentSimulateRequest(BaseModel):
    project_id: str
    user_message: str
    tools: list[str] = ["read_file"]
    source_file_ids: list[str] = []


@router.post("/agent/simulate")
def simulate_agent(req: AgentSimulateRequest):
    task_id = new_id("task_agent")
    events = []
    alerts = []

    llm_event = record_event(
        {
            "project_id": req.project_id,
            "task_id": task_id,
            "actor_type": "agent",
            "actor_id": "agent_demo",
            "action": "llm.call",
            "resource_type": "prompt",
            "context": {"user_message": req.user_message, "source_file_ids": req.source_file_ids},
        }
    )
    events.append({"event_id": llm_event["event_id"], "action": "llm.call", "decision": llm_event["decision"]})
    if llm_event.get("alert_id"):
        alerts.append(llm_event["alert_id"])

    target_path = "/Users/demo/Desktop/secret.txt" if "secret" in req.user_message.lower() or "桌面" in req.user_message else "storage/projects/demo/normal.txt"
    file_event = record_event(
        {
            "project_id": req.project_id,
            "task_id": task_id,
            "actor_type": "agent",
            "actor_id": "agent_demo",
            "action": "file.read",
            "resource_type": "file",
            "resource_path": target_path,
            "context": {"user_message": req.user_message, "tool_name": "read_file"},
        }
    )
    events.append({"event_id": file_event["event_id"], "action": "file.read", "decision": file_event["decision"]})
    if file_event.get("alert_id"):
        alerts.append(file_event["alert_id"])

    final_decision = "deny" if any(item["decision"] == "deny" for item in events) else "allow"
    reply = "该请求涉及越权文件读取，已被安全策略阻断。" if final_decision == "deny" else "模拟智能体任务已完成。"
    return ok({"task_id": task_id, "status": "completed", "final_decision": final_decision, "reply": reply, "events": events, "alerts": alerts})

