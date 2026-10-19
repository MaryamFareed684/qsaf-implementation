"""
domains/domain4_output_risk/controls/or_006_prompt_response_correlation.py

QSAF-OR-006: Prompt-response correlation analysis (hybrid, egress).

What it does, in plain words:
  1. Takes the important words of the user's prompt (stop words removed, simple stemming).
  2. Counts how many of them show up in the agent's reply = "coverage".
  3. Very low coverage means the reply probably ignores the question or answers
     something else (a sign of a hijacked or confused agent).

"Hybrid": the real-time check runs now, and the coverage numbers are stored in the
evidence so they can be analysed later in batch (for example, trends per session).

Limits: it is lexical. A correct answer that uses different words can score low,
so the result is only ever a warning, capped at a modest risk. Very short replies
and refusals are skipped. Embedding similarity could be added later.
Evidence holds numbers only, never the prompt or reply words.
"""

import re

from core.control_base import Control
from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy

POLICY_FOLDER = "domain4_output_risk"
POLICY_KEY = "or_006_prompt_response"

_WORD = re.compile(r"[a-z0-9]+")


def _stem(word: str) -> str:
    for suffix in ("ing", "ed", "es", "s"):
        if len(word) > len(suffix) + 3 and word.endswith(suffix):
            return word[: -len(suffix)]
    return word


def _keywords(text: str, stopwords: set) -> set:
    return {_stem(w) for w in _WORD.findall(text.lower()) if len(w) >= 3 and w not in stopwords}


class PromptResponseCorrelationOR006(Control):
    control_id = "OR-006"
    domain = "Domain 4: Output Risk & Response Control"
    layer = "egress"

    def evaluate(self, ctx: RequestContext) -> Verdict:
        cfg = load_domain_policy(POLICY_FOLDER).get(POLICY_KEY)
        if not cfg:
            return self._verdict("warn", 0.5, f"OR-006 policy section '{POLICY_KEY}' is missing from policy.yaml; reply was not checked.", {})
        if not cfg.get("enabled", True):
            return self._verdict("pass", 0.0, "OR-006 is disabled in policy.yaml.", {})

        try:
            stopwords = set(cfg.get("stopwords", []))
            min_keywords = int(cfg["min_prompt_keywords"])
            min_reply_words = int(cfg["min_reply_words"])
            ok_overlap = float(cfg["ok_overlap"])
            warn_threshold = float(cfg["warn_threshold"])
            max_risk = float(cfg["max_risk"])
            refusal_patterns = cfg.get("refusal_patterns", [])
        except (KeyError, TypeError, ValueError) as exc:
            return self._verdict("warn", 0.5, f"OR-006 policy values are invalid ({type(exc).__name__}); reply was not checked.", {})

        reply = ctx.agent_output
        if reply is None or not str(reply).strip():
            return self._verdict("pass", 0.0, "No agent output to compare.", {})
        reply = str(reply)
        prompt = ctx.raw_prompt or ""

        # Cases where we deliberately do not judge.
        reply_words = len(reply.split())
        if reply_words < min_reply_words:
            return self._verdict("pass", 0.0, "Reply is too short to judge relevance.", {"skipped": "short_reply", "reply_words": reply_words})
        for pattern in refusal_patterns:
            try:
                if re.search(pattern, reply):
                    return self._verdict("pass", 0.0, "Reply is a refusal; relevance check skipped.", {"skipped": "refusal"})
            except re.error:
                continue

        prompt_keys = _keywords(prompt, stopwords)
        if len(prompt_keys) < min_keywords:
            return self._verdict("pass", 0.0, "Prompt has too few key words to judge relevance.", {"skipped": "short_prompt", "prompt_keywords": len(prompt_keys)})

        reply_keys = _keywords(reply, stopwords)
        matched = len(prompt_keys & reply_keys)
        coverage = matched / len(prompt_keys)

        if coverage >= ok_overlap:
            risk = 0.0
        else:
            risk = max_risk * (ok_overlap - coverage) / ok_overlap
        risk = round(min(max(risk, 0.0), 1.0), 3)
        status = "warn" if risk >= warn_threshold else "pass"

        evidence = {
            "prompt_keywords": len(prompt_keys),
            "matched_keywords": matched,
            "coverage": round(coverage, 3),
            "ok_overlap": ok_overlap,
            "reply_words": reply_words,
        }
        if status == "warn":
            reason = (f"Reply may not answer the question: only {matched} of {len(prompt_keys)} key prompt words "
                      f"appear in it (coverage {coverage:.2f}, risk {risk:.2f}).")
        else:
            reason = f"Reply is related to the prompt ({matched} of {len(prompt_keys)} key words covered, coverage {coverage:.2f})."
        return self._verdict(status, risk, reason, evidence)

    def _verdict(self, status: str, score: float, reason: str, evidence: dict) -> Verdict:
        return Verdict(control_id=self.control_id, domain=self.domain, status=status,
                       risk_score=score, reason=reason, evidence=evidence)
