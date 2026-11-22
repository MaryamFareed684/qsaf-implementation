from core.control_base import Control
from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy


class RiskScoringPI004(Control):
    control_id = "PI-004"
    domain = "Domain 1: Prompt Injection Protection"
    layer = "ingress"

    STATUS_SEVERITY = {
        "pass": 0,
        "warn": 1,
        "escalate": 2,
        "block": 3,
    }

    DEFAULT_ESCALATING_FAILURES = ("refused", "not_json", "invalid_score")

    def _escalating_failures(self):
        """Judge failure kinds that need a human, from policy.yaml (risk_scoring.escalate_on_analyzer_failure)."""
        policy = load_domain_policy("domain1_prompt_injection")
        kinds = policy.get("risk_scoring", {}).get("escalate_on_analyzer_failure")
        if isinstance(kinds, list) and all(isinstance(k, str) for k in kinds):
            return tuple(kinds)
        return self.DEFAULT_ESCALATING_FAILURES

    def evaluate(self, ctx: RequestContext) -> Verdict:
        # PI-004 expects prior verdicts to already be collected somewhere.
        # Per the contract, extra data flows through ctx.metadata, so the
        # orchestrator places prior verdicts there before calling PI-004.
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

        # Maximum risk_score wins: keeps status and score telling the same story
        max_risk_score = max(v.risk_score for v in prior_verdicts)

        contributing = [
            {"control_id": v.control_id, "status": v.status, "risk_score": v.risk_score}
            for v in prior_verdicts
        ]
        evidence = {"contributing_verdicts": contributing}
        reason = f"Aggregated {len(prior_verdicts)} control verdict(s); worst outcome: {final_status}."

        # Nothing blocked, but the LLM judge could not decide: the automated judgment is incomplete,
        # so a human should look (PI-006 writes the alert).
        if final_status in ("pass", "warn"):
            kinds = self._escalating_failures()
            undecided = [v for v in prior_verdicts if (v.evidence or {}).get("analyzer_failure") in kinds]
            if undecided:
                first = undecided[0]
                kind = first.evidence["analyzer_failure"]
                final_status = "escalate"
                evidence["escalation_reason"] = {"control_id": first.control_id, "analyzer_failure": kind}
                reason = (f"Aggregated {len(prior_verdicts)} control verdict(s); {first.control_id} could not decide "
                          f"({kind}), so a human should review.")

        return Verdict(
            control_id=self.control_id,
            domain=self.domain,
            status=final_status,
            risk_score=max_risk_score,
            reason=reason,
            evidence=evidence,
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