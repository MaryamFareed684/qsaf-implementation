from core.control_base import Control
from core.models import RequestContext, Verdict


class RiskScoringPI004(Control):
    control_id = "PI-004"
    domain = "Domain 1: Prompt Injection Protection"
    layer = "ingress"

    STATUS_SEVERITY = {
        "pass": 0,
        "warn": 1,
        "block": 2,
        "escalate": 3,
    }

    def evaluate(self, ctx: RequestContext) -> Verdict:
        # PI-004 expects prior verdicts to already be collected somewhere.
        # Per the contract, extra data flows through ctx.metadata — so the
        # orchestrator is expected to place prior verdicts there before
        # calling PI-004.
        prior_verdicts = ctx.metadata.get("prior_verdicts", [])

        if not prior_verdicts:
            return Verdict(
                control_id=self.control_id,
                domain=self.domain,
                status="pass",
                risk_score=0.0,
                reason="No prior verdicts available to score.",
                evidence={},
            )

        # Worst status wins
        worst_verdict = max(prior_verdicts, key=lambda v: self.STATUS_SEVERITY[v.status])
        final_status = worst_verdict.status

        # Maximum risk_score wins — keeps status and score telling the same story
        max_risk_score = max(v.risk_score for v in prior_verdicts)

        contributing = [
            {"control_id": v.control_id, "status": v.status, "risk_score": v.risk_score}
            for v in prior_verdicts
        ]

        return Verdict(
            control_id=self.control_id,
            domain=self.domain,
            status=final_status,
            risk_score=max_risk_score,
            reason=f"Aggregated {len(prior_verdicts)} control verdict(s); worst outcome: {final_status}.",
            evidence={"contributing_verdicts": contributing},
        )


if __name__ == "__main__":
    from core.models import RequestContext

    # Simulate PI-008 (pass), PI-001 (block), PI-003 (block) having already run
    fake_prior = [
        Verdict(control_id="PI-008", domain="Domain 1: Prompt Injection Protection",
                status="pass", risk_score=0.0, reason="Sanitized."),
        Verdict(control_id="PI-001", domain="Domain 1: Prompt Injection Protection",
                status="block", risk_score=0.9, reason="Blacklist match."),
        Verdict(control_id="PI-003", domain="Domain 1: Prompt Injection Protection",
                status="block", risk_score=0.65, reason="Semantic similarity."),
    ]

    ctx = RequestContext(session_id="t1", user_id="maryam", raw_prompt="test")
    ctx.metadata["prior_verdicts"] = fake_prior

    control = RiskScoringPI004()
    verdict = control.evaluate(ctx)
    print("Status:", verdict.status)
    print("Risk score:", verdict.risk_score)
    print("Reason:", verdict.reason)
    print("Contributing:", verdict.evidence["contributing_verdicts"])