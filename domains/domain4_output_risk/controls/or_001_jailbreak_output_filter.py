"""
domains/domain4_output_risk/controls/or_001_jailbreak_output_filter.py

QSAF-OR-001: Content filter for jailbreak or illegal content (real-time, egress).

What it does, in plain words:
  1. Takes the agent's reply (ctx.agent_output).
  2. "Cleans" the text so simple tricks do not hide bad content
     (invisible characters, leetspeak like D4N, accents, b.o.m.b spacing).
  3. Checks it against the rules in config/policy.yaml. Each rule has a weight.
  4. Combines the matches into one risk score (several weak signals add up).
  5. If the reply is clearly a refusal or a news-style report, lowers the score.
  6. Turns the score into pass / warn / block / escalate using policy thresholds.

Privacy: the Verdict never contains the reply text or the matched words.
Only rule ids, categories and numbers go into `evidence`, so the shared audit
log stays safe.
"""

import re
import unicodedata

from core.control_base import Control
from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy

POLICY_FOLDER = "domain4_output_risk"
POLICY_KEY = "or_001_content_filter"

# --- text clean-up tables (these are not tunable thresholds, just the cleaner) ---
_INVISIBLE_CHARS = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad"), None)
_LEETSPEAK = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_SPACED_LETTERS = re.compile(r"\b(?:[a-z] ){2,}[a-z]\b")


def _join_spaced_letters(text: str) -> str:
    """'b o m b' -> 'bomb'. A leading single-letter word ('a b o m b') stays separate."""
    def _join(match: re.Match) -> str:
        letters = match.group(0).split(" ")
        prefix = ""
        if letters[0] in ("a", "i") and len(letters) >= 4:
            prefix = letters[0] + " "
            letters = letters[1:]
        return prefix + "".join(letters)
    return _SPACED_LETTERS.sub(_join, text)


def normalise(text: str) -> str:
    """Lower-case, strip invisible chars and accents, undo leetspeak, tidy separators."""
    text = text.translate(_INVISIBLE_CHARS)
    text = unicodedata.normalize("NFKD", text)
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    text = text.lower().translate(_LEETSPEAK)
    text = re.sub(r"[\s_\-\.\*]+", " ", text)
    return _join_spaced_letters(text.strip())


class JailbreakOutputFilterOR001(Control):
    # KEEP the original values from the stub for these three lines.
    control_id = "OR-001"
    domain = "Domain 4: Output Risk & Response Control"
    layer = "egress"

    # ------------------------------------------------------------------ public
    def evaluate(self, ctx: RequestContext) -> Verdict:
        # 1) Load this control's policy section. Missing/broken config -> safe warn.
        cfg = load_domain_policy(POLICY_FOLDER).get(POLICY_KEY)
        if not cfg:
            return self._verdict(
                "warn", 0.5,
                f"OR-001 policy section '{POLICY_KEY}' is missing from policy.yaml; reply was not checked.",
                {"policy_key": POLICY_KEY},
            )
        if not cfg.get("enabled", True):
            return self._verdict("pass", 0.0, "OR-001 is disabled in policy.yaml.", {})

        try:
            warn_threshold = float(cfg["warn_threshold"])
            block_threshold = float(cfg["block_threshold"])
            discount = float(cfg["safe_context_discount"])
            escalate_categories = set(cfg.get("escalate_categories", []))
            rules = cfg.get("rules", [])
        except (KeyError, TypeError, ValueError) as exc:
            return self._verdict(
                "warn", 0.5,
                f"OR-001 policy values are invalid ({type(exc).__name__}); reply was not checked.",
                {"policy_key": POLICY_KEY},
            )

        # 2) Nothing to inspect. (Blank/null output is Domain 10's job, not ours.)
        reply = ctx.agent_output
        if reply is None or not str(reply).strip():
            return self._verdict("pass", 0.0, "No agent output to inspect.", {})

        text = normalise(str(reply))

        # 3) Run the rules. A rule with a broken pattern is skipped, not fatal.
        matched, invalid = [], []
        for rule in rules:
            try:
                if re.search(rule["pattern"], text, re.IGNORECASE):
                    matched.append(rule)
            except (re.error, KeyError, TypeError):
                invalid.append(str(rule.get("id", "?")) if isinstance(rule, dict) else "?")

        # 4) Combine weights with noisy-OR: 1 - (1-w1)(1-w2)...
        remaining = 1.0
        for rule in matched:
            remaining *= 1.0 - float(rule.get("weight", 0.0))
        raw_score = 1.0 - remaining

        # 5) Refusal / news-report context lowers the score (never removes it).
        safe_context = bool(matched) and self._has_safe_context(text, cfg.get("safe_context_patterns", []), invalid)
        score = raw_score * discount if safe_context else raw_score
        score = round(min(max(score, 0.0), 1.0), 3)

        categories = sorted({str(r.get("category", "unknown")) for r in matched})
        rule_ids = [str(r.get("id", "?")) for r in matched]

        # 6) Score -> status
        if score >= block_threshold:
            status = "escalate" if escalate_categories & set(categories) else "block"
        elif score >= warn_threshold:
            status = "warn"
        else:
            status = "pass"

        evidence = {
            "matched_rule_ids": rule_ids,
            "categories": categories,
            "score_before_context": round(raw_score, 3),
            "safe_context_applied": safe_context,
            "thresholds": {"warn": warn_threshold, "block": block_threshold},
            "reply_length": len(str(reply)),
        }
        if invalid:
            evidence["invalid_rules"] = invalid

        return self._verdict(status, score, self._reason(status, score, categories, rule_ids, safe_context), evidence)

    # ----------------------------------------------------------------- helpers
    def _verdict(self, status: str, score: float, reason: str, evidence: dict) -> Verdict:
        return Verdict(
            control_id=self.control_id,
            domain=self.domain,
            status=status,
            risk_score=score,
            reason=reason,
            evidence=evidence,
        )

    @staticmethod
    def _has_safe_context(text: str, patterns: list, invalid: list) -> bool:
        for pattern in patterns:
            try:
                if re.search(pattern, text, re.IGNORECASE):
                    return True
            except re.error:
                invalid.append("safe_context_pattern")
        return False

    @staticmethod
    def _reason(status: str, score: float, categories: list, rule_ids: list, safe_context: bool) -> str:
        if not rule_ids:
            return "No jailbreak or illegal-content patterns found in the agent reply (risk 0.00)."
        label = {"warn": "Warning", "block": "Blocked", "escalate": "Escalated for human review", "pass": "Passed"}[status]
        note = " Refusal/report wording lowered the score." if safe_context else ""
        return (
            f"{label}: {len(rule_ids)} rule(s) matched ({', '.join(rule_ids)}) "
            f"in category(ies) {', '.join(categories)}; risk {score:.2f}.{note}"
        )
