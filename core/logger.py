"""
core/logger.py

ONE shared audit logging pipeline. No domain should implement its own
logging file/format — everyone calls log_verdict() / log_pipeline_result()
so the whole team's output lands in one consistent, queryable log.
"""

import json
import os
from datetime import datetime, timezone

from core.models import Verdict, PipelineResult

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs", "audit")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "qsaf_audit_log.jsonl")


def _write(record: dict):
    record["logged_at"] = datetime.now(timezone.utc).isoformat()
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def log_verdict(session_id: str, verdict: Verdict):
    _write(
        {
            "type": "verdict",
            "session_id": session_id,
            "control_id": verdict.control_id,
            "domain": verdict.domain,
            "status": verdict.status,
            "risk_score": verdict.risk_score,
            "reason": verdict.reason,
            "evidence": verdict.evidence,
        }
    )


def log_pipeline_result(result: PipelineResult):
    _write(
        {
            "type": "pipeline_result",
            "session_id": result.session_id,
            "final_status": result.final_status,
            "overall_risk_score": result.overall_risk_score,
            "blocked_by": result.blocked_by,
            "num_verdicts": len(result.verdicts),
        }
    )


def read_recent_logs(n: int = 50) -> list[dict]:
    """Used by the dashboard to show recent activity."""
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()[-n:]
    return [json.loads(line) for line in lines]
