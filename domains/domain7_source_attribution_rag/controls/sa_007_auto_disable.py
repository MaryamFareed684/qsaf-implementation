"""
SA-007: Auto-disable RAG pipeline upon anomaly (Real-Time)
Domain: Domain 7: Source Attribution & RAG Monitoring

Session-level control. A request is "anomalous" when any other Domain 7 verdict
(SA-001..SA-006) in ctx.metadata["prior_verdicts"] has a blocking status, per the policy list of
statuses. SA-007 keeps a sliding window per session; when enough recent
requests are anomalous it returns block with evidence["rag_disabled"] = True.
The state is latched until reset_session() is called by an operator.

A control may not mutate ctx, so "disabling" means: this verdict plus the
helper is_rag_disabled(session_id) that the calling pipeline reads.

Known limits: state is in memory only (lost on restart) and not thread-safe;
the shared orchestrator stops a layer at the first block and never fills
prior_verdicts, so the caller must run all Domain 7 controls and supply their
verdicts (demo_domain7.py does).
"""

from collections import deque

from core.control_base import Control
from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy

DOMAIN_FOLDER = "domain7_source_attribution_rag"

_SESSIONS: dict[str, dict] = {}   # session_id -> {"window": deque[bool], "disabled": bool}


def reset_session(session_id: str) -> None:
    _SESSIONS.pop(session_id, None)


def reset_all() -> None:
    _SESSIONS.clear()


def is_rag_disabled(session_id: str) -> bool:
    return bool(_SESSIONS.get(session_id, {}).get("disabled", False))


class AutoDisableSA007(Control):
    control_id = "SA-007"
    domain = "Domain 7: Source Attribution & RAG Monitoring"
    layer = "egress"

    def _verdict(self, status, risk, reason, evidence=None):
        return Verdict(
            control_id=self.control_id,
            domain=self.domain,
            status=status,
            risk_score=risk,
            reason=reason,
            evidence=evidence or {},
        )

    def evaluate(self, ctx: RequestContext) -> Verdict:
        policy = load_domain_policy(DOMAIN_FOLDER).get("auto_disable")
        if not policy:
            return self._verdict("warn", 0.5, "Missing 'auto_disable' section in policy.yaml.")
        if not policy.get("enabled", True):
            return self._verdict("pass", 0.0, "Auto-disable disabled in policy.")

        sid = ctx.session_id
        state = _SESSIONS.setdefault(
            sid, {"window": deque(maxlen=int(policy["window"])), "disabled": False}
        )

        if state["disabled"]:
            return self._verdict(
                "block", float(policy["disable_risk"]),
                "RAG pipeline is disabled for this session after repeated anomalies.",
                {"session_id": sid, "rag_disabled": True},
            )

        sa_verdicts = [
            v for v in ctx.metadata.get("prior_verdicts", [])
            if str(v.control_id).startswith("SA-") and v.control_id != self.control_id
        ]
        if not sa_verdicts:
            return self._verdict(
                "warn", float(policy["missing_input_risk"]),
                "No Domain 7 verdicts in ctx.metadata['prior_verdicts']; cannot assess this request.",
                {"session_id": sid, "rag_disabled": False},
            )

        triggering = [v.control_id for v in sa_verdicts
                      if v.status in policy["anomaly_statuses"]]
        anomalous = bool(triggering)
        state["window"].append(anomalous)
        count = sum(state["window"])

        evidence = {
            "session_id": sid,
            "anomalous_this_request": anomalous,
            "triggering_controls": triggering,
            "anomalies_in_window": int(count),
            "window": int(policy["window"]),
            "max_anomalies": int(policy["max_anomalies"]),
            "rag_disabled": False,
        }

        if count >= policy["max_anomalies"]:
            state["disabled"] = True
            evidence["rag_disabled"] = True
            return self._verdict(
                "block", float(policy["disable_risk"]),
                f"{count} of the last {len(state['window'])} requests were anomalous: RAG pipeline disabled for this session.",
                evidence,
            )
        if anomalous:
            return self._verdict(
                "warn", float(policy["warn_risk"]),
                f"Anomalous request ({count}/{policy['max_anomalies']} before RAG is disabled): {', '.join(triggering)}.",
                evidence,
            )
        return self._verdict("pass", 0.0, "No anomaly in this request.", evidence)