"""
SA-003: Calculate hallucination likelihood score (Real-Time)
Domain: Domain 7: Source Attribution & RAG Monitoring

Combines two signals into one score between 0 and 1:
  1. the share of answer sentences SA-002 found unsupported (read from
     ctx.metadata["prior_verdicts"], the same convention RC-006 uses), and
  2. the share of numbers and mid-sentence capitalised words in the answer
     that appear in none of the retrieved documents.

Known limits: negation errors ("covers" vs "does not cover") contain no
numbers or names, so they are not detected; numbers written as words and names
at the start of a sentence are not compared.
"""

import re

from core.control_base import Control
from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy

DOMAIN_FOLDER = "domain7_source_attribution_rag"

_NUMBER = re.compile(r"\d+(?:[.,]\d+)?")


def _sentences(text: str) -> list[str]:
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+", text) if s.strip()]


def extract_facts(answer: str) -> tuple[list[str], list[str]]:
    """Return (numbers, names) found in the answer. Names = capitalised words
    that are not the first word of a sentence."""
    numbers, names = [], []
    for sent in _sentences(answer):
        numbers.extend(_NUMBER.findall(sent))
        for token in sent.split()[1:]:
            word = token.strip(".,;:!?()[]\"'")
            if len(word) >= 2 and word.isalpha() and word[0].isupper():
                names.append(word)
    return numbers, names


class HallucinationScoreSA003(Control):
    control_id = "SA-003"
    domain = "Domain 7: Source Attribution & RAG Monitoring"
    layer = "egress"

    def _verdict(self, status, risk, reason, evidence=None):
        return Verdict(
            control_id=self.control_id,
            domain=self.domain,
            status=status,
            risk_score=risk,
            reason=reason,
            evidence=evidence or {},
        )

    def evaluate(self, ctx: RequestContext) -> Verdict:
        policy = load_domain_policy(DOMAIN_FOLDER).get("hallucination_score")
        if not policy:
            return self._verdict("warn", 0.5, "Missing 'hallucination_score' section in policy.yaml.")
        if not policy.get("enabled", True):
            return self._verdict("pass", 0.0, "Hallucination scoring disabled in policy.")

        answer = (ctx.agent_output or "").strip()
        if not answer:
            return self._verdict("pass", 0.0, "No agent output to score.")

        sa002 = next(
            (v for v in ctx.metadata.get("prior_verdicts", []) if v.control_id == "SA-002"),
            None,
        )
        if sa002 is None or "unsupported_ratio" not in sa002.evidence:
            return self._verdict(
                "warn", float(policy["missing_input_risk"]),
                "SA-002 result not available in ctx.metadata['prior_verdicts']; cannot score.",
            )
        text_ratio = float(sa002.evidence["unsupported_ratio"])

        doc_text = " ".join(str(d.get("text", "")) for d in ctx.retrieved_docs)
        doc_numbers = set(_NUMBER.findall(doc_text))
        doc_words = {w.lower() for w in re.findall(r"[A-Za-z]+", doc_text)}

        citation_pattern = (load_domain_policy(DOMAIN_FOLDER).get("attribution") or {}).get(
            "citation_pattern", r"\[([A-Za-z0-9_.-]+)\]")
        answer_for_facts = re.sub(citation_pattern, " ", answer)  # citation ids such as [kb-001] are not facts
        numbers, names = extract_facts(answer_for_facts)
        bad_numbers = [n for n in numbers if n not in doc_numbers]
        bad_names = [n for n in names if n.lower() not in doc_words]
        total_facts = len(numbers) + len(names)
        fact_ratio = (len(bad_numbers) + len(bad_names)) / total_facts if total_facts else 0.0

        score = policy["weight_text"] * text_ratio + policy["weight_facts"] * fact_ratio
        score = round(float(min(1.0, max(0.0, score))), 3)

        evidence = {
            "hallucination_score": score,
            "unsupported_ratio": round(text_ratio, 3),
            "ungrounded_fact_ratio": round(float(fact_ratio), 3),
            "ungrounded_numbers": bad_numbers,
            "ungrounded_names": bad_names,
        }

        if score >= policy["block_threshold"]:
            status, reason = "block", f"High hallucination likelihood ({score})."
        elif score >= policy["warn_threshold"]:
            status, reason = "warn", f"Possible hallucination ({score})."
        else:
            status, reason = "pass", f"Low hallucination likelihood ({score})."
        return self._verdict(status, score, reason, evidence)