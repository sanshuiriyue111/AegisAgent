import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
STORAGE_DIR = Path(os.environ.get("AEGIS_STORAGE_DIR", str(BASE_DIR / "storage"))).expanduser().resolve()
FILES_DIR = STORAGE_DIR / "files"
REDTEAM_CASES_DIR = STORAGE_DIR / "redteam_cases"
DB_PATH = STORAGE_DIR / "aegisagent.db"

FILES_DIR.mkdir(parents=True, exist_ok=True)
REDTEAM_CASES_DIR.mkdir(parents=True, exist_ok=True)

