"""
domains/domain4_output_risk/controls/or_007_tone_deviation.py

QSAF-OR-007: Tone and sentiment deviation tracking (real-time, egress).

What it does, in plain words:
  1. Scores the sentiment of this reply on a -1 (negative) to +1 (positive) scale
     using small word lists from policy.yaml.
  2. Looks at the agent's EARLIER replies in ctx.conversation_history. If this reply's
     sentiment is very different from its usual tone, that is a "deviation".
  3. Independently of history, flags hostile, threatening, manipulative or dismissive
     wording and SHOUTING (many capitals or exclamation marks).
  4. Combines the signals into one risk score: pass / warn / block.

Why it matters: a sudden change of tone can mean the agent was hijacked, role-played
into a different persona, or is pressuring the user.

Limits: lexicon based, English only. It never reads or stores the reply text in the
evidence, only numbers and signal ids.
"""

import re

from core.control_base import Control
from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy

POLICY_FOLDER = "domain4_output_risk"
POLICY_KEY = "or_007_tone_deviation"

_WORD = re.compile(r"[A-Za-z']+")


def _sentiment(text: str, positive: set, negative: set, min_words: int):
    """Return sentiment in [-1, 1], or None if the text has too few sentiment words."""
    words = [w.lower() for w in _WORD.findall(text)]
    pos = sum(1 for w in words if w in positive)
    neg = sum(1 for w in words if w in negative)
    if pos + neg < min_words:
        return None
    return (pos - neg) / (pos + neg)


def _message_text(item) -> str:
    if isinstance(item, dict):
        for key in ("content", "text", "message"):
            if isinstance(item.get(key), str):
                return item[key]
    return ""


class ToneDeviationOR007(Control):
    control_id = "OR-007"
    domain = "Domain 4: Output Risk & Response Control"
    layer = "egress"

    def evaluate(self, ctx: RequestContext) -> Verdict:
        cfg = load_domain_policy(POLICY_FOLDER).get(POLICY_KEY)
        if not cfg:
            return self._verdict("warn", 0.5, f"OR-007 policy section '{POLICY_KEY}' is missing from policy.yaml; reply was not checked.", {})
        if not cfg.get("enabled", True):
            return self._verdict("pass", 0.0, "OR-007 is disabled in policy.yaml.", {})

        try:
            min_history = int(cfg["min_history_replies"])
            min_sent_words = int(cfg["min_sentiment_words"])
            dev_threshold = float(cfg["deviation_threshold"])
            dev_weight = float(cfg["deviation_weight"])
            dev_max = float(cfg["deviation_max_weight"])
            warn_threshold = float(cfg["warn_threshold"])
            block_threshold = float(cfg["block_threshold"])
            roles = {str(r).lower() for r in cfg.get("assistant_roles", [])}
            positive = {str(w).lower() for w in cfg.get("positive_words", [])}
            negative = {str(w).lower() for w in cfg.get("negative_words", [])}
            shout = cfg["shouting"]
            shout_min_words = int(shout["min_words"])
            shout_caps = float(shout["caps_ratio"])
            shout_excl = int(shout["exclamation_count"])
            shout_weight = float(shout["weight"])
            signals = cfg.get("signals", [])
        except (KeyError, TypeError, ValueError) as exc:
            return self._verdict("warn", 0.5, f"OR-007 policy values are invalid ({type(exc).__name__}); reply was not checked.", {})

        reply = ctx.agent_output
        if reply is None or not str(reply).strip():
            return self._verdict("pass", 0.0, "No agent output to inspect.", {})
        reply = str(reply)

        weights, found, flag_ids, invalid = [], [], [], []

        # --- wording signals
        for sig in signals:
            try:
                if re.search(sig["pattern"], reply):
                    flag_ids.append(str(sig.get("id", "?")))
                    weights.append(float(sig.get("weight", 0.0)))
                    found.append(str(sig.get("category", "signal")))
            except (re.error, KeyError, TypeError, ValueError):
                invalid.append(str(sig.get("id", "?")) if isinstance(sig, dict) else "?")

        # --- shouting
        words = reply.split()
        letters_words = [w for w in words if sum(c.isalpha() for c in w) >= 2]
        caps_words = [w for w in letters_words if w.isupper()]
        caps_ratio = len(caps_words) / len(letters_words) if letters_words else 0.0
        exclamations = reply.count("!")
        shouting = (len(words) >= shout_min_words and caps_ratio >= shout_caps) or exclamations >= shout_excl
        if shouting:
            weights.append(shout_weight)
            found.append("shouting")

        # --- sentiment deviation from this agent's earlier replies
        current = _sentiment(reply, positive, negative, min_sent_words)
        history_scores = []
        for item in ctx.conversation_history:
            if isinstance(item, dict) and str(item.get("role", "")).lower() in roles:
                s = _sentiment(_message_text(item), positive, negative, min_sent_words)
                if s is not None:
                    history_scores.append(s)
        baseline = deviation = None
        if current is not None and len(history_scores) >= min_history:
            baseline = sum(history_scores) / len(history_scores)
            deviation = abs(current - baseline)
            if deviation >= dev_threshold:
                weights.append(min(dev_weight * deviation / dev_threshold, dev_max))
                found.append("sentiment shift")

        remaining = 1.0
        for w in weights:
            remaining *= 1.0 - w
        score = round(1.0 - remaining, 3)

        if score >= block_threshold:
            status = "block"
        elif score >= warn_threshold:
            status = "warn"
        else:
            status = "pass"

        evidence = {
            "flag_ids": flag_ids,
            "shouting": shouting,
            "caps_ratio": round(caps_ratio, 3),
            "exclamations": exclamations,
            "current_sentiment": None if current is None else round(current, 3),
            "baseline_sentiment": None if baseline is None else round(baseline, 3),
            "deviation": None if deviation is None else round(deviation, 3),
            "history_replies_used": len(history_scores),
        }
        if invalid:
            evidence["invalid_rules"] = invalid

        if status == "pass":
            reason = "Tone is normal for this conversation (risk {:.2f}).".format(score) if not found else \
                f"Minor tone signals ({', '.join(found)}) below the warning level (risk {score:.2f})."
        else:
            reason = f"Unusual tone detected: {', '.join(found)} (risk {score:.2f})."
        return self._verdict(status, score, reason, evidence)

    def _verdict(self, status: str, score: float, reason: str, evidence: dict) -> Verdict:
        return Verdict(control_id=self.control_id, domain=self.domain, status=status,
                       risk_score=score, reason=reason, evidence=evidence)
