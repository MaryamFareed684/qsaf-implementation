"""
domains/domain4_output_risk/controls/or_005_risky_reroute.py

QSAF-OR-005: Block or reroute risky content (real-time, egress).

This is the DECISION ENGINE of Domain 4. The other controls detect; this one decides.

It runs the Domain 4 detectors itself (OR-001, 002, 004, 006, 007), so it does not depend on
the order the orchestrator runs controls in. Then it decides in TWO independent ways and
takes the MORE SEVERE answer:

  1) MANDATORY RULES (policy.yaml -> mandatory_rules). Hard rules such as "if OR-004 found a
     private key, block, no matter what the other scores are". They exist so that a critical
     risk can never be hidden by averaging it with harmless scores.

  2) WEIGHTED SCORE. Each detector's risk is multiplied by a weight and combined (noisy-OR).
     Many moderate signals can add up past the block line.

Possible actions, most severe first (order set in policy.yaml -> action_priority):
     escalate_to_moderator -> a human must decide
     block                 -> drop the reply completely
     reroute               -> replace the reply with a safe fallback message
     allow_with_warning    -> deliver, but flag it
     allow                 -> deliver

The shared Verdict only knows pass / warn / block / escalate, so "reroute" is expressed as status
"block" plus evidence["action"] = "reroute" and the fallback message.

Evidence says which rules fired and whether a rule or the score made the decision, so a human
reviewer can see WHY. It never contains the reply text.
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

_STATUS_FOR_ACTION = {
    "escalate_to_moderator": "escalate",
    "block": "block",
    "reroute": "block",
    "allow_with_warning": "warn",
    "allow": "pass",
}


def _categories_of(verdict: Verdict) -> set:
    """Categories a detector reported (OR-001 'categories', OR-004 'findings')."""
    evidence = verdict.evidence or {}
    found = {str(c) for c in evidence.get("categories", [])}
    found |= {str(f.get("category")) for f in evidence.get("findings", []) if isinstance(f, dict)}
    return found


def rule_matches(rule: dict, verdict: Verdict) -> bool:
    """A rule fires only if EVERY condition it lists is true (control, status_in, min_risk, category_in)."""
    control = str(rule.get("control", "any"))
    if control != "any" and control != verdict.control_id:
        return False
    if "status_in" in rule and verdict.status not in rule["status_in"]:
        return False
    if "min_risk" in rule and verdict.risk_score < float(rule["min_risk"]):
        return False
    if "category_in" in rule and not (_categories_of(verdict) & {str(c) for c in rule["category_in"]}):
        return False
    return True


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
            priority = [str(a) for a in cfg["action_priority"]]
            default_block_action = str(cfg["default_block_action"])
            fallback = str(cfg["fallback_message"])
            rules = cfg.get("mandatory_rules", [])
            if default_block_action not in priority:
                raise ValueError("default_block_action is not in action_priority")
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            return self._verdict("warn", 0.5, f"OR-005 policy values are invalid ({type(exc).__name__}); no decision was made.", {})

        if ctx.agent_output is None or not str(ctx.agent_output).strip():
            return self._verdict("pass", 0.0, "No agent output to act on.", {"action": "allow"})

        verdicts = [d.safe_evaluate(ctx) for d in self._detectors]

        # --- weighted score (noisy-OR of weight x risk)
        remaining = 1.0
        for v in verdicts:
            remaining *= 1.0 - min(max(weights.get(v.control_id, 0.0) * v.risk_score, 0.0), 1.0)
        combined = round(1.0 - remaining, 3)
        top_risk = max(v.risk_score for v in verdicts)

        if combined >= block_threshold:
            score_action = default_block_action
        elif combined >= warn_threshold:
            score_action = "allow_with_warning"
        else:
            score_action = "allow"

        # --- mandatory rules: collect every rule that fires
        fired, invalid = [], []
        for rule in rules:
            try:
                action = str(rule["action"])
                if action not in priority:
                    raise ValueError("unknown action")
                if any(rule_matches(rule, v) for v in verdicts):
                    fired.append((str(rule.get("id", "?")), action))
            except (KeyError, TypeError, ValueError, AttributeError):
                invalid.append(str(rule.get("id", "?")) if isinstance(rule, dict) else "?")

        # --- take the MORE SEVERE of the rule decision and the score decision
        rank = {action: i for i, action in enumerate(priority)}      # lower number = more severe
        decided_by, action = "weighted_score", score_action
        for rule_id, rule_action in fired:
            if rank[rule_action] < rank[action]:
                action, decided_by = rule_action, f"mandatory_rule:{rule_id}"

        contributors = [{"control_id": v.control_id, "status": v.status, "risk": round(v.risk_score, 3)}
                        for v in verdicts if v.status != "pass"]
        evidence = {
            "action": action,
            "decided_by": decided_by,
            "fired_rules": [rule_id for rule_id, _ in fired],
            "combined_risk": combined,
            "contributors": contributors,
            "thresholds": {"warn": warn_threshold, "block": block_threshold},
        }
        if invalid:
            evidence["invalid_rules"] = invalid

        status = _STATUS_FOR_ACTION.get(action, "block")
        risk = round(min(max(combined, top_risk), 1.0), 3)
        ids = ", ".join(c["control_id"] for c in contributors) or "no detector"

        if action == "escalate_to_moderator":
            reason = f"Escalated to a human moderator: {ids} requested review ({decided_by})."
        elif action == "block":
            reason = f"Blocked: reply not delivered because of {ids} ({decided_by}, combined risk {combined:.2f})."
        elif action == "reroute":
            evidence["fallback_message"] = fallback
            reason = f"Rerouted: reply replaced by a safe message because of {ids} ({decided_by}, combined risk {combined:.2f})."
        elif action == "allow_with_warning":
            reason = f"Delivered with a warning: combined risk {combined:.2f} from {ids}."
        else:
            reason = f"Reply allowed (combined risk {combined:.2f})."
            risk = combined
        return self._verdict(status, risk, reason, evidence)

    def _verdict(self, status: str, score: float, reason: str, evidence: dict) -> Verdict:
        return Verdict(control_id=self.control_id, domain=self.domain, status=status,
                       risk_score=round(min(max(score, 0.0), 1.0), 3), reason=reason, evidence=evidence)
