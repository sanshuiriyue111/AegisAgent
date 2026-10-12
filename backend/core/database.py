import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from core.config import DB_PATH
from modules.policy.default_policies import DEFAULT_POLICIES
from modules.redteam.cases import DEFAULT_REDTEAM_CASES, ensure_redteam_samples


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    import uuid

    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def loads(value: str | None, default=None):
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = get_conn()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS projects (
          project_id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          description TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS files (
          file_id TEXT PRIMARY KEY,
          project_id TEXT NOT NULL,
          file_name TEXT NOT NULL,
          file_type TEXT NOT NULL,
          file_size INTEGER NOT NULL,
          sha256 TEXT,
          storage_path TEXT NOT NULL,
          risk_score INTEGER DEFAULT 0,
          risk_level TEXT DEFAULT 'info',
          scan_status TEXT DEFAULT 'pending',
          created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scan_tasks (
          task_id TEXT PRIMARY KEY,
          project_id TEXT NOT NULL,
          target_type TEXT NOT NULL,
          target_id TEXT NOT NULL,
          status TEXT NOT NULL,
          progress INTEGER DEFAULT 0,
          result_json TEXT,
          created_at TEXT NOT NULL,
          completed_at TEXT
        );

        CREATE TABLE IF NOT EXISTS security_events (
          event_id TEXT PRIMARY KEY,
          project_id TEXT NOT NULL,
          task_id TEXT,
          actor_type TEXT,
          actor_id TEXT,
          action TEXT NOT NULL,
          resource_type TEXT,
          resource_id TEXT,
          resource_path TEXT,
          risk_score INTEGER DEFAULT 0,
          risk_level TEXT DEFAULT 'info',
          decision TEXT DEFAULT 'allow',
          rule_ids_json TEXT,
          evidence_json TEXT,
          context_json TEXT,
          created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS alerts (
          alert_id TEXT PRIMARY KEY,
          project_id TEXT NOT NULL,
          event_id TEXT,
          title TEXT NOT NULL,
          category TEXT NOT NULL,
          severity TEXT NOT NULL,
          status TEXT DEFAULT 'open',
          decision TEXT,
          description TEXT,
          recommendation TEXT,
          evidence_json TEXT,
          attack_chain_json TEXT,
          matched_rules_json TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS policies (
          policy_id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          category TEXT NOT NULL,
          enabled INTEGER DEFAULT 1,
          severity TEXT NOT NULL,
          decision TEXT NOT NULL,
          description TEXT,
          config_json TEXT,
          hit_count INTEGER DEFAULT 0,
          updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS redteam_cases (
          case_id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          category TEXT NOT NULL,
          description TEXT,
          sample_file TEXT,
          expected_decision TEXT,
          enabled INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS redteam_runs (
          run_id TEXT PRIMARY KEY,
          project_id TEXT NOT NULL,
          status TEXT NOT NULL,
          summary_json TEXT,
          result_json TEXT,
          created_at TEXT NOT NULL,
          completed_at TEXT
        );
        """
    )
    conn.commit()
    conn.close()


def seed_defaults():
    ensure_redteam_samples()
    conn = get_conn()
    now = now_iso()
    for policy in DEFAULT_POLICIES:
        conn.execute(
            """
            INSERT OR IGNORE INTO policies
            (policy_id, name, category, enabled, severity, decision, description, config_json, hit_count, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
            """,
            (
                policy["policy_id"],
                policy["name"],
                policy["category"],
                1 if policy.get("enabled", True) else 0,
                policy["severity"],
                policy["decision"],
                policy.get("description", ""),
                dumps(policy.get("config", {})),
                now,
            ),
        )
    for case in DEFAULT_REDTEAM_CASES:
        conn.execute(
            """
            INSERT INTO redteam_cases
            (case_id, name, category, description, sample_file, expected_decision, enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(case_id) DO UPDATE SET
              name=excluded.name,
              category=excluded.category,
              description=excluded.description,
              sample_file=excluded.sample_file,
              expected_decision=excluded.expected_decision,
              enabled=excluded.enabled
            """,
            (
                case["case_id"],
                case["name"],
                case["category"],
                case["description"],
                case["sample_file"],
                case["expected_decision"],
                1,
            ),
        )
    conn.commit()
    conn.close()


def row_to_dict(row):
    if row is None:
        return None
    return dict(row)


def rows_to_dicts(rows):
    return [dict(row) for row in rows]
