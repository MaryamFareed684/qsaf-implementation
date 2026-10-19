"""
domains/domain4_output_risk/controls/or_004_sensitivity_scoring.py

QSAF-OR-004: Sensitivity scoring of LLM responses (real-time, egress).

What it does, in plain words:
  1. Looks in the agent's reply for personal data and secrets:
     emails, phone numbers, card numbers (checked with the Luhn formula so random
     digits are ignored), national ID numbers, bank accounts, API keys,
     "password: ..." lines and private-key blocks.
  2. Gives every category a score: more items = higher score (never above the cap).
  3. Combines the categories into ONE sensitivity score from 0 to 1.
  4. pass / warn / block using thresholds from policy.yaml.

Privacy: the audit log shows MASKED samples only (j***@example.com, ************1111).
The full detected value is never stored.
"""

import re

from core.control_base import Control
from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy

POLICY_FOLDER = "domain4_output_risk"
POLICY_KEY = "or_004_sensitivity"


def luhn_ok(number: str) -> bool:
    """Card-number checksum. Random digit strings usually fail it."""
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def mask_value(style: str, value: str) -> str:
    """Hide most of a detected value so logs stay safe."""
    if style == "email":
        local, _, domain = value.partition("@")
        return f"{local[:1]}***@{domain}"
    if style == "tail4":
        keep = "".join(c for c in value if c.isalnum())[-4:]
        return "*" * 8 + keep
    # head3 (keys, passwords, private keys): show only the first 3 characters
    return value[:3] + "***"


class SensitivityScoringOR004(Control):
    control_id = "OR-004"
    domain = "Domain 4: Output Risk & Response Control"
    layer = "egress"

    def evaluate(self, ctx: RequestContext) -> Verdict:
        cfg = load_domain_policy(POLICY_FOLDER).get(POLICY_KEY)
        if not cfg:
            return self._verdict("warn", 0.5, f"OR-004 policy section '{POLICY_KEY}' is missing from policy.yaml; reply was not checked.", {})
        if not cfg.get("enabled", True):
            return self._verdict("pass", 0.0, "OR-004 is disabled in policy.yaml.", {})

        try:
            warn_threshold = float(cfg["warn_threshold"])
            block_threshold = float(cfg["block_threshold"])
            category_cap = float(cfg["category_cap"])
            max_samples = int(cfg["max_samples"])
            rules = cfg.get("rules", [])
        except (KeyError, TypeError, ValueError) as exc:
            return self._verdict("warn", 0.5, f"OR-004 policy values are invalid ({type(exc).__name__}); reply was not checked.", {})

        reply = ctx.agent_output
        if reply is None or not str(reply).strip():
            return self._verdict("pass", 0.0, "No agent output to inspect.", {})
        reply = str(reply)

        # --- find matches (earlier rules win; later rules ignore text already matched)
        used_spans = []
        categories = {}   # category -> {"label", "weight", "count", "samples"}
        invalid = []
        for rule in rules:
            try:
                pattern = re.compile(rule["pattern"])
                weight = float(rule["weight"])
                category = str(rule["category"])
            except (re.error, KeyError, TypeError, ValueError):
                invalid.append(str(rule.get("id", "?")) if isinstance(rule, dict) else "?")
                continue
            for match in pattern.finditer(reply):
                start, end = match.span()
                if any(start < e and end > s for s, e in used_spans):
                    continue
                if rule.get("validator") == "luhn" and not luhn_ok(match.group(0)):
                    continue
                used_spans.append((start, end))
                entry = categories.setdefault(category, {"label": str(rule.get("label", category)), "weight": 0.0, "count": 0, "samples": []})
                entry["weight"] = max(entry["weight"], weight)
                entry["count"] += 1
                if len(entry["samples"]) < max_samples:
                    entry["samples"].append(mask_value(str(rule.get("mask", "head3")), match.group(0)))

        # --- score: per category 1-(1-w)^count (capped), then combine categories
        remaining = 1.0
        findings = []
        for category, entry in categories.items():
            cat_score = min(1.0 - (1.0 - entry["weight"]) ** entry["count"], category_cap)
            remaining *= 1.0 - cat_score
            findings.append({"category": category, "count": entry["count"], "category_score": round(cat_score, 3), "masked_samples": entry["samples"]})
        score = round(1.0 - remaining, 3)

        if score >= block_threshold:
            status = "block"
        elif score >= warn_threshold:
            status = "warn"
        else:
            status = "pass"

        evidence = {"sensitivity_score": score, "findings": findings, "thresholds": {"warn": warn_threshold, "block": block_threshold}}
        if invalid:
            evidence["invalid_rules"] = invalid

        if not categories:
            reason = "No sensitive data found in the agent reply (sensitivity 0.00)."
        else:
            parts = [f"{e['count']} {e['label']}{'s' if e['count'] > 1 else ''}" for e in categories.values()]
            joined = parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]
            reason = f"Contains {joined} (sensitivity {score:.2f})."
        return self._verdict(status, score, reason, evidence)

    def _verdict(self, status: str, score: float, reason: str, evidence: dict) -> Verdict:
        return Verdict(control_id=self.control_id, domain=self.domain, status=status,
                       risk_score=score, reason=reason, evidence=evidence)
