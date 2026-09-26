"""
RC-005: Nested / Multi-turn Injection Detector
Domain: Domain 2: Role & Context Manipulation

STATUS: DUMMY STUB — replace evaluate() with real logic.
Owner: <assign teammate name here>

This stub exists so the pipeline is runnable end-to-end from day one.
Do NOT change the class name, control_id, domain, or layer without
discussing with the team lead (it will break the orchestrator registry).
"""

from core.control_base import Control
from core.models import RequestContext, Verdict


class NestedInjectionRC005(Control):
    control_id = "RC-005"
    domain = "Domain 2: Role & Context Manipulation"
    layer = "ingress"

    def evaluate(self, ctx: RequestContext) -> Verdict:
        # TODO: implement real detection logic here.
        # Load thresholds via core.policy_loader.load_domain_policy(...)
        # instead of hardcoding numbers.
        return Verdict(
            control_id=self.control_id,
            domain=self.domain,
            status="pass",
            risk_score=0.0,
            reason="Dummy stub — not yet implemented.",
            evidence={},
        )
