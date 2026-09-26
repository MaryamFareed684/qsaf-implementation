"""
core/risk_engine.py

Combines a list of Verdicts (from many controls, possibly many domains)
into ONE final PipelineResult. This is the only place "final decision"
logic should live — individual controls should never try to decide the
overall outcome themselves, only report on their own narrow check.
"""

from core.models import Verdict, PipelineResult

# Order matters: if ANY verdict has this status, the final status is at
# least this severe. "block" beats "escalate" beats "warn" beats "pass".
_SEVERITY_ORDER = {"pass": 0, "warn": 1, "escalate": 2, "block": 3}


def aggregate(session_id: str, verdicts: list[Verdict]) -> PipelineResult:
    if not verdicts:
        return PipelineResult(
            session_id=session_id,
            final_status="pass",
            overall_risk_score=0.0,
            verdicts=[],
        )

    worst = max(verdicts, key=lambda v: _SEVERITY_ORDER[v.status])
    overall_risk_score = max(v.risk_score for v in verdicts)

    blocked_by = worst.control_id if worst.status in ("block", "escalate") else None

    return PipelineResult(
        session_id=session_id,
        final_status=worst.status,
        overall_risk_score=round(overall_risk_score, 3),
        verdicts=verdicts,
        blocked_by=blocked_by,
    )
