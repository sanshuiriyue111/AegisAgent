import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from main import app


def assert_ok(resp, label):
    if resp.status_code != 200:
        raise AssertionError(f"{label} HTTP {resp.status_code}: {resp.text}")
    body = resp.json()
    if body.get("code") != 200:
        raise AssertionError(f"{label} API error: {body}")
    return body["data"]


def main():
    client = TestClient(app)
    with client:
        project = assert_ok(
            client.post("/api/v1/projects", json={"name": "API 滥用检测测试", "description": "连续异常 API 请求"}),
            "create project",
        )
        project_id = project["project_id"]
        actor_id = "api_abuse_tester"
        final_event = None
        for index in range(10):
            final_event = assert_ok(
                client.post(
                    "/api/v1/events",
                    json={
                        "project_id": project_id,
                        "actor_type": "redteam",
                        "actor_id": actor_id,
                        "action": "api.request",
                        "resource_type": "api",
                        "resource_id": f"missing_file_{index}",
                        "resource_path": f"/api/v1/files/missing_file_{index}",
                        "context": {"method": "GET", "status_code": 404, "path": f"/api/v1/files/missing_file_{index}"},
                    },
                ),
                f"api event {index}",
            )

        if final_event["decision"] != "alert_only":
            raise AssertionError(f"expected final decision alert_only, got {final_event}")
        if not final_event.get("alert_id"):
            raise AssertionError(f"expected api abuse alert, got {final_event}")
        alert = assert_ok(client.get(f"/api/v1/alerts/{final_event['alert_id']}"), "alert detail")
        if alert["category"] != "api_abuse":
            raise AssertionError(f"expected api_abuse alert, got {alert}")

        print("[OK] API abuse detection")
        print(f"project_id={project_id}")
        print(f"event_id={final_event['event_id']}")
        print(f"alert_id={final_event['alert_id']}")


if __name__ == "__main__":
    main()

