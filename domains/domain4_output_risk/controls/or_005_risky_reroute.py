"""
domains/domain4_output_risk/controls/or_005_risky_reroute.py

QSAF-OR-005: Block or reroute risky content (real-time, egress).

This is the ACTION control of Domain 4. The other controls detect; this one decides.

What it does, in plain words:
  1. Runs the Domain 4 detectors itself (OR-001, 002, 004, 006, 007), so it does not
     depend on the order the orchestrator runs controls in.
  2. Combines their risk scores (each multiplied by a weight from policy.yaml).
  3. Picks one ACTION:
        allow              -> nothing found
        allow_with_warning -> moderate risk, deliver but flag
        reroute            -> replace the reply with a safe fallback message
        block              -> drop the reply completely
        escalate_to_moderator -> a detector asked for a human to decide

The shared Verdict only knows pass / warn / block / escalate, so a reroute is
expressed as status "block" plus evidence["action"] = "reroute" and the
fallback message. (If the team's risk engine later supports a real "reroute"
status, only this file changes.)
"""

from core.control_base import Control
from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy
from domains.domain4_output_risk.controls.or_001_jailbreak_output_filter import JailbreakOutputFilterOR001
from domains.domain4_output_risk.controls.or_002_hallucination_flag import HallucinationFlagOR002
from domains.domain4_output_risk.controls.or_004_sensitivity_scoring import SensitivityScoringOR004
from domains.domain4_output_risk.controls.or_006_prompt_response_correlation import PromptResponseCorrelationOR006
from domains.domain4_output_risk.controls.or_007_tone_deviation import ToneDeviationOR007

POLICY_FOLDER = "domain4_output_risk"
POLICY_KEY = "or_005_risky_reroute"


class RiskyRerouteOR005(Control):
    control_id = "OR-005"
    domain = "Domain 4: Output Risk & Response Control"
    layer = "egress"

    def __init__(self):
        super().__init__()
        self._detectors = [
            JailbreakOutputFilterOR001(),
            HallucinationFlagOR002(),
            SensitivityScoringOR004(),
            PromptResponseCorrelationOR006(),
            ToneDeviationOR007(),
        ]

    def evaluate(self, ctx: RequestContext) -> Verdict:
        cfg = load_domain_policy(POLICY_FOLDER).get(POLICY_KEY)
        if not cfg:
            return self._verdict("warn", 0.5, f"OR-005 policy section '{POLICY_KEY}' is missing from policy.yaml; no decision was made.", {})
        if not cfg.get("enabled", True):
            return self._verdict("pass", 0.0, "OR-005 is disabled in policy.yaml.", {"action": "allow"})

        try:
            warn_threshold = float(cfg["warn_threshold"])
            block_threshold = float(cfg["block_threshold"])
            weights = {str(k): float(v) for k, v in cfg["control_weights"].items()}
            action_by_control = {str(k): str(v) for k, v in cfg.get("action_by_control", {}).items()}
            default_block_action = str(cfg["default_block_action"])
            fallback = str(cfg["fallback_message"])
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            return self._verdict("warn", 0.5, f"OR-005 policy values are invalid ({type(exc).__name__}); no decision was made.", {})

        if ctx.agent_output is None or not str(ctx.agent_output).strip():
            return self._verdict("pass", 0.0, "No agent output to act on.", {"action": "allow"})

        verdicts = [d.safe_evaluate(ctx) for d in self._detectors]

        # Combined risk: noisy-OR of (weight x risk) for each detector.
        remaining = 1.0
        for v in verdicts:
            remaining *= 1.0 - min(max(weights.get(v.control_id, 0.0) * v.risk_score, 0.0), 1.0)
        combined = round(1.0 - remaining, 3)
        top_risk = max(v.risk_score for v in verdicts)

        contributors = [
            {"control_id": v.control_id, "status": v.status, "risk": round(v.risk_score, 3)}
            for v in verdicts if v.status != "pass"
        ]
        evidence = {"combined_risk": combined, "contributors": contributors,
                    "thresholds": {"warn": warn_threshold, "block": block_threshold}}

        escalating = [v for v in verdicts if v.status == "escalate"]
        blockers = [v for v in verdicts if v.status == "block"]

        # 1) A detector asked for a human.
        if escalating:
            evidence["action"] = "escalate_to_moderator"
            ids = ", ".join(v.control_id for v in escalating)
            return self._verdict("escalate", max(combined, top_risk),
                                 f"Escalated to a human moderator: {ids} requested review.", evidence)

        # 2) A detector said block -> choose block or reroute by control.
        if blockers:
            actions = {action_by_control.get(v.control_id, default_block_action) for v in blockers}
            action = "block" if "block" in actions else "reroute"
            return self._block_verdict(action, max(combined, top_risk), ", ".join(v.control_id for v in blockers), fallback, evidence)

        # 3) Many moderate signals add up past the block line.
        if combined >= block_threshold:
            ids = ", ".join(c["control_id"] for c in contributors)
            return self._block_verdict(default_block_action, combined, ids, fallback, evidence)

        # 4) Moderate risk: deliver, but flag it.
        if combined >= warn_threshold:
            evidence["action"] = "allow_with_warning"
            ids = ", ".join(c["control_id"] for c in contributors)
            return self._verdict("warn", combined, f"Delivered with a warning: combined risk {combined:.2f} from {ids}.", evidence)

        evidence["action"] = "allow"
        return self._verdict("pass", combined, f"Reply allowed (combined risk {combined:.2f}).", evidence)

    # ----------------------------------------------------------------- helpers
    def _block_verdict(self, action: str, risk: float, ids: str, fallback: str, evidence: dict) -> Verdict:
        evidence["action"] = action
        if action == "reroute":
            evidence["fallback_message"] = fallback
            reason = f"Rerouted: reply replaced by a safe message because of {ids} (combined risk {risk:.2f})."
        else:
            reason = f"Blocked: reply not delivered because of {ids} (combined risk {risk:.2f})."
        return self._verdict("block", min(risk, 1.0), reason, evidence)

    def _verdict(self, status: str, score: float, reason: str, evidence: dict) -> Verdict:
        return Verdict(control_id=self.control_id, domain=self.domain, status=status,
                       risk_score=round(min(max(score, 0.0), 1.0), 3), reason=reason, evidence=evidence)
