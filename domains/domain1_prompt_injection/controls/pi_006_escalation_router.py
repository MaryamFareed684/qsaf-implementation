from core.control_base import Control
from core.models import RequestContext, Verdict
import json
import os
from datetime import datetime, timezone


ALERT_LOG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))),
    "logs", "audit", "escalation_alerts.jsonl"
)


class EscalationRouterPI006(Control):
    control_id = "PI-006"
    domain = "Domain 1: Prompt Injection Protection"
    layer = "ingress"

    def evaluate(self, ctx: RequestContext) -> Verdict:
        final_verdict = ctx.metadata.get("final_verdict")

        if final_verdict is None or final_verdict.status != "escalate":
            return Verdict(
                control_id=self.control_id,
                domain=self.domain,
                status="pass",
                risk_score=0.0,
                reason="No escalation needed.",
                evidence={},
            )

        # "Route" the alert — write it to a clearly separate alert log
        os.makedirs(os.path.dirname(ALERT_LOG_PATH), exist_ok=True)
        alert_record = {
            "alert": "HUMAN REVIEW NEEDED",
            "session_id": ctx.session_id,
            "triggering_control": final_verdict.control_id,
            "risk_score": final_verdict.risk_score,
            "reason": final_verdict.reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with open(ALERT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert_record) + "\n")

        print(f"[ESCALATION ALERT] Session {ctx.session_id} flagged for human review: {final_verdict.reason}")

        return Verdict(
            control_id=self.control_id,
            domain=self.domain,
            status="escalate",
            risk_score=final_verdict.risk_score,
            reason=f"Escalated to human review log: {final_verdict.reason}",
            evidence={"alert_logged": True},
        )


if __name__ == "__main__":
    ctx = RequestContext(session_id="test-escalate", user_id="maryam", raw_prompt="test")
    ctx.metadata["final_verdict"] = Verdict(
        control_id="PI-004", domain="Domain 1: Prompt Injection Protection",
        status="escalate", risk_score=0.75,
        reason="Ambiguous high-risk prompt requiring human judgment.",
    )
    verdict = EscalationRouterPI006().evaluate(ctx)
    print("Status:", verdict.status, "| Reason:", verdict.reason)