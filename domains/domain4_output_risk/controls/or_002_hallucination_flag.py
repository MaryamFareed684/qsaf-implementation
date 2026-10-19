"""
domains/domain4_output_risk/controls/or_002_hallucination_flag.py

QSAF-OR-002: Flag hallucinated facts in responses (real-time, egress).

Honest limit: no program can know the truth. So this control NEVER says
"hallucination proven". It only warns when it sees weak signals:

  A) If we have source material (ctx.retrieved_docs): sentences with numbers or
     names that the documents do not support.
  B) Always: URLs or emails that nobody mentioned before (likely invented),
     very precise statistics, "according to a study" with no source,
     citation-shaped text, and overconfident wording.

Result is pass or warn only, with a modest, capped risk score.
Evidence holds counts and signal ids, never the reply text.
"""

import re

from core.control_base import Control
from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy

POLICY_FOLDER = "domain4_output_risk"
POLICY_KEY = "or_002_hallucination"

_URL = re.compile(r"(?:https?://|www\.)[^\s)>\]\"']+", re.IGNORECASE)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_WORD = re.compile(r"[a-z0-9]+")
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")


def _strings_in(obj) -> list:
    """Collect every text value from nested dicts/lists (docs, history, tool results)."""
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in _strings_in(v)]
    if isinstance(obj, (list, tuple)):
        return [s for v in obj for s in _strings_in(v)]
    return []


def _stem(word: str) -> str:
    for suffix in ("ing", "ed", "es", "s"):
        if len(word) > len(suffix) + 3 and word.endswith(suffix):
            return word[: -len(suffix)]
    return word


def _content_words(text: str, stopwords: set) -> set:
    return {_stem(w) for w in _WORD.findall(text.lower()) if len(w) >= 3 and w not in stopwords}


class HallucinationFlagOR002(Control):
    control_id = "OR-002"
    domain = "Domain 4: Output Risk & Response Control"
    layer = "egress"

    def evaluate(self, ctx: RequestContext) -> Verdict:
        cfg = load_domain_policy(POLICY_FOLDER).get(POLICY_KEY)
        if not cfg:
            return self._verdict("warn", 0.5, f"OR-002 policy section '{POLICY_KEY}' is missing from policy.yaml; reply was not checked.", {})
        if not cfg.get("enabled", True):
            return self._verdict("pass", 0.0, "OR-002 is disabled in policy.yaml.", {})

        try:
            warn_threshold = float(cfg["warn_threshold"])
            max_risk = float(cfg["max_risk"])
            url_weight = float(cfg["unsourced_url_weight"])
            email_weight = float(cfg["unsourced_email_weight"])
            stopwords = set(cfg.get("stopwords", []))
            signals = cfg.get("signals", [])
            grounding = cfg.get("grounding", {})
        except (KeyError, TypeError, ValueError) as exc:
            return self._verdict("warn", 0.5, f"OR-002 policy values are invalid ({type(exc).__name__}); reply was not checked.", {})

        reply = ctx.agent_output
        if reply is None or not str(reply).strip():
            return self._verdict("pass", 0.0, "No agent output to inspect.", {})
        reply = str(reply)

        # Everything the agent was legitimately given. Used to decide if a URL/email was "invented".
        doc_texts = _strings_in(ctx.retrieved_docs)
        source_blob = " ".join([ctx.raw_prompt or ""] + _strings_in(ctx.conversation_history) + doc_texts + _strings_in(ctx.tool_calls)).lower()

        weights, found = [], []   # found = human-readable parts for the reason

        # --- signal patterns from policy
        matched_ids, invalid = [], []
        for sig in signals:
            try:
                if re.search(sig["pattern"], reply):
                    matched_ids.append(str(sig.get("id", "?")))
                    weights.append(float(sig.get("weight", 0.0)))
                    found.append(str(sig.get("category", "signal")).replace("_", " "))
            except (re.error, KeyError, TypeError, ValueError):
                invalid.append(str(sig.get("id", "?")) if isinstance(sig, dict) else "?")

        # --- URLs and emails nobody mentioned before
        urls = {u.rstrip(".,;:!?").lower() for u in _URL.findall(reply)}
        unsourced_urls = [u for u in urls if u not in source_blob]
        if unsourced_urls:
            weights.append(url_weight)
            found.append(f"{len(unsourced_urls)} unsourced URL(s)")
        emails = {e.lower() for e in _EMAIL.findall(reply)}
        unsourced_emails = [e for e in emails if e not in source_blob]
        if unsourced_emails:
            weights.append(email_weight)
            found.append(f"{len(unsourced_emails)} unsourced email address(es)")

        # --- grounding against retrieved documents (only if we have some)
        mode = "weak_signals"
        claims_checked = claims_unsupported = 0
        if grounding.get("enabled", True) and any(t.strip() for t in doc_texts):
            mode = "grounded"
            try:
                doc_words = _content_words(" ".join(doc_texts), stopwords)
                min_words = int(grounding["min_claim_words"])
                support = float(grounding["support_overlap"])
                min_claims = int(grounding["min_checkable_claims"])
                ratio_warn = float(grounding["unsupported_ratio_warn"])
                unsupported_weight = float(grounding["unsupported_weight"])
                for sentence in _SENTENCE_SPLIT.split(reply):
                    tokens = sentence.split()
                    if len(tokens) < min_words:
                        continue
                    has_number = bool(re.search(r"\d", sentence))
                    has_name = any(t[:1].isupper() and t[1:].islower() for t in tokens[1:])
                    if not (has_number or has_name):
                        continue
                    words = _content_words(sentence, stopwords)
                    if not words:
                        continue
                    claims_checked += 1
                    if len(words & doc_words) / len(words) < support:
                        claims_unsupported += 1
                if claims_checked >= min_claims and claims_unsupported / claims_checked >= ratio_warn:
                    weights.append(unsupported_weight)
                    found.append(f"{claims_unsupported} of {claims_checked} checkable claim(s) not supported by the documents")
            except (KeyError, TypeError, ValueError):
                invalid.append("grounding_config")

        remaining = 1.0
        for w in weights:
            remaining *= 1.0 - w
        score = round(min(1.0 - remaining, max_risk), 3)
        status = "warn" if score >= warn_threshold else "pass"

        evidence = {
            "mode": mode,
            "matched_signal_ids": matched_ids,
            "unsourced_urls": len(unsourced_urls),
            "unsourced_emails": len(unsourced_emails),
            "claims_checked": claims_checked,
            "claims_unsupported": claims_unsupported,
            "risk_cap": max_risk,
        }
        if invalid:
            evidence["invalid_rules"] = invalid

        if status == "warn":
            reason = f"Possible unsupported facts: {', '.join(found)}. Weak signals only, not proof of hallucination (risk {score:.2f})."
        elif found:
            reason = f"Minor signals only ({', '.join(found)}); below the warning level (risk {score:.2f})."
        else:
            reason = "No hallucination warning signs found (risk 0.00)."
        return self._verdict(status, score, reason, evidence)

    def _verdict(self, status: str, score: float, reason: str, evidence: dict) -> Verdict:
        return Verdict(control_id=self.control_id, domain=self.domain, status=status,
                       risk_score=score, reason=reason, evidence=evidence)
