from core.control_base import Control
from core.models import RequestContext, Verdict
import json
import os
from datetime import datetime, timezone


ROLE_ASSERTION_LOG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))),
    "logs", "audit", "role_assertion_log.jsonl"
)


class RoleAssertionLogRC006(Control):
    control_id = "RC-006"
    domain = "Domain 2: Role & Context Manipulation"
    layer = "ingress"

    def evaluate(self, ctx: RequestContext) -> Verdict:
        # Check if RC-001 or RC-002 (earlier controls) already flagged this prompt
        prior_verdicts = ctx.metadata.get("prior_verdicts", [])
        role_related = [
            v for v in prior_verdicts
            if v.control_id in ("RC-001", "RC-002", "RC-004") and v.status != "pass"
        ]

        if not role_related:
            return Verdict(
                control_id=self.control_id,
                domain=self.domain,
                status="pass",
                risk_score=0.0,
                reason="No role assertion events to log.",
                evidence={},
            )

        os.makedirs(os.path.dirname(ROLE_ASSERTION_LOG_PATH), exist_ok=True)
        record = {
            "session_id": ctx.session_id,
            "user_id": ctx.user_id,
            "triggering_controls": [v.control_id for v in role_related],
            "details": [{"control_id": v.control_id, "reason": v.reason} for v in role_related],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with open(ROLE_ASSERTION_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

        return Verdict(
            control_id=self.control_id,
            domain=self.domain,
            status="pass",  # logging itself is never a block — it just records
            risk_score=0.0,
            reason=f"Logged {len(role_related)} role assertion event(s) for audit.",
            evidence={"logged_controls": [v.control_id for v in role_related]},
        )


if __name__ == "__main__":
    # Simulate RC-001 having already flagged something
    fake_prior = [
        Verdict(control_id="RC-001", domain="Domain 2: Role & Context Manipulation",
                status="warn", risk_score=0.6, reason="Prompt contains 1 role-switching phrase(s)."),
    ]
    ctx = RequestContext(session_id="test-log", user_id="maryam", raw_prompt="test")
    ctx.metadata["prior_verdicts"] = fake_prior
    v = RoleAssertionLogRC006().evaluate(ctx)
    print("Status:", v.status, "| Reason:", v.reason)