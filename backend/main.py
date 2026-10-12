from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from api.projects import router as projects_router
from api.files import router as files_router
from api.scans import router as scans_router
from api.events import router as events_router
from api.alerts import router as alerts_router
from api.policies import router as policies_router
from api.dashboard import router as dashboard_router
from api.redteam import router as redteam_router
from api.agent_simulator import router as agent_router
from api.demo import router as demo_router
from core.database import init_db, seed_defaults


app = FastAPI(
    title="AegisAgent API",
    description="Agent security audit and behavior supervision platform",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    init_db()
    seed_defaults()


@app.get("/api/v1/health")
def health():
    return {"code": 200, "message": "success", "data": {"status": "ok"}}


app.include_router(projects_router, prefix="/api/v1")
app.include_router(files_router, prefix="/api/v1")
app.include_router(scans_router, prefix="/api/v1")
app.include_router(events_router, prefix="/api/v1")
app.include_router(alerts_router, prefix="/api/v1")
app.include_router(policies_router, prefix="/api/v1")
app.include_router(dashboard_router, prefix="/api/v1")
app.include_router(redteam_router, prefix="/api/v1")
app.include_router(agent_router, prefix="/api/v1")
app.include_router(demo_router, prefix="/api/v1")


FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/console", StaticFiles(directory=FRONTEND_DIR, html=True), name="console")
