from core.control_base import Control
from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy


class MultiPhaseValidatorPI005(Control):
    control_id = "PI-005"
    domain = "Domain 1: Prompt Injection Protection"
    layer = "ingress"

    STATUS_SEVERITY = {
        "pass": 0,
        "warn": 1,
        "block": 2,
        "escalate": 3,
    }

    def evaluate(self, ctx: RequestContext) -> Verdict:
        policy = load_domain_policy("domain1_prompt_injection")
        config = policy.get("multi_phase_validator", {})
        stop_threshold = config.get("stop_on_status", "block")  # stop early if any verdict is this bad or worse

        # Verdicts from the fast controls that already ran (PI-008, PI-001, PI-007)
        early_verdicts = ctx.metadata.get("prior_verdicts", [])

        if not early_verdicts:
            return Verdict(
                control_id=self.control_id,
                domain=self.domain,
                status="pass",
                risk_score=0.0,
                reason="No prior verdicts to evaluate; proceeding to next phase.",
                evidence={"proceed_to_expensive_checks": True},
            )

        worst_verdict = max(early_verdicts, key=lambda v: self.STATUS_SEVERITY[v.status])
        stop_severity = self.STATUS_SEVERITY[stop_threshold]
        worst_severity = self.STATUS_SEVERITY[worst_verdict.status]

        should_stop = worst_severity >= stop_severity

        return Verdict(
            control_id=self.control_id,
            domain=self.domain,
            status=worst_verdict.status,
            risk_score=worst_verdict.risk_score,
            reason=(
                f"Early phase already found '{worst_verdict.status}' from {worst_verdict.control_id}; "
                f"{'stopping pipeline early' if should_stop else 'proceeding to deeper analysis'}."
            ),
            evidence={
                "proceed_to_expensive_checks": not should_stop,
                "triggering_control": worst_verdict.control_id,
            },
        )


if __name__ == "__main__":
    # Simulate PI-008 (pass) and PI-001 (block) having already run
    early_block = [
        Verdict(control_id="PI-008", domain="Domain 1: Prompt Injection Protection",
                status="pass", risk_score=0.0, reason="Sanitized."),
        Verdict(control_id="PI-001", domain="Domain 1: Prompt Injection Protection",
                status="block", risk_score=0.9, reason="Blacklist match."),
    ]
    ctx1 = RequestContext(session_id="t1", user_id="maryam", raw_prompt="test")
    ctx1.metadata["prior_verdicts"] = early_block
    v1 = MultiPhaseValidatorPI005().evaluate(ctx1)
    print("--- Early block case ---")
    print("Status:", v1.status, "| Proceed to PI-002?:", v1.evidence["proceed_to_expensive_checks"])

    # Simulate everything passing so far
    early_pass = [
        Verdict(control_id="PI-008", domain="Domain 1: Prompt Injection Protection",
                status="pass", risk_score=0.0, reason="Sanitized."),
        Verdict(control_id="PI-001", domain="Domain 1: Prompt Injection Protection",
                status="pass", risk_score=0.0, reason="No match."),
    ]
    ctx2 = RequestContext(session_id="t2", user_id="maryam", raw_prompt="test")
    ctx2.metadata["prior_verdicts"] = early_pass
    v2 = MultiPhaseValidatorPI005().evaluate(ctx2)
    print("--- Early pass case ---")
    print("Status:", v2.status, "| Proceed to PI-002?:", v2.evidence["proceed_to_expensive_checks"])