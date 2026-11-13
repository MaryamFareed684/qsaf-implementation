"""
SA-003: Calculate hallucination likelihood score (Real-Time)
Domain: Domain 7: Source Attribution & RAG Monitoring

Score = weight_text * (share of answer sentences SA-002 found unsupported, read from
ctx.metadata["prior_verdicts"], the RC-006 convention)
      + step_ungrounded_fact * (numbers and mid-sentence capitalised words found in no
        CITED document; all retrieved documents if nothing valid is cited)
      + step_conflict * (supported sentences that contradict their best-matching document
        sentence: negation mismatch or an antonym pair from the policy).
Refusal sentences are not claims and are ignored.

Known limits: numbers written as words and names at the start of a sentence are not
compared; a wrong number that appears elsewhere in the same cited document is not caught;
the contradiction check is a heuristic (it can flag paraphrases such as "does not cost
anything" for "is free").
"""

import re

from core.control_base import Control
from core.models import RequestContext, Verdict
from domains.domain7_source_attribution_rag import common

_NUMBER = re.compile(r"\d+(?:[.,]\d+)?")


def extract_facts(answer: str) -> tuple[list[str], list[str]]:
    """Return (numbers, names) found in the answer. Names = capitalised words
    that are not the first word of a sentence."""
    numbers, names = [], []
    for sent in common.split_sentences(answer):
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
        if common.rag_not_used(ctx):
            return self._verdict("pass", 0.0, "RAG not used for this request; Domain 7 does not apply.", {"rag_used": False})
        full = common.load_policy()
        policy = full.get("hallucination_score")
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

        pattern = common.citation_pattern(full)
        cited = set(re.findall(pattern, answer))
        pool = [d for d in ctx.retrieved_docs if str(d.get("doc_id", "")) in cited] or list(ctx.retrieved_docs)
        pool_text = " ".join(str(d.get("text", "")) for d in pool)
        doc_numbers = set(_NUMBER.findall(pool_text))
        doc_words = {w.lower() for w in re.findall(r"[A-Za-z]+", pool_text)}

        refusal_policy = full.get("refusal")
        sentences = common.split_sentences(common.strip_citations(answer, pattern))
        claims = [s for s in sentences if not common.is_refusal_sentence(s, refusal_policy)]
        numbers, names = extract_facts(" ".join(claims))
        bad_numbers = [n for n in numbers if n not in doc_numbers]
        bad_names = [n for n in names if n.lower() not in doc_words]

        conflicts = []
        for rec in sa002.evidence.get("sentences", []):
            if not rec.get("supported"):
                continue
            kind = common.polarity_conflict(
                rec.get("text", ""), rec.get("best_doc_sentence", ""), policy.get("antonym_pairs", []))
            if kind:
                conflicts.append({"sentence": rec["text"], "doc_sentence": rec["best_doc_sentence"], "kind": kind})

        n_facts = len(bad_numbers) + len(bad_names)
        score = (policy["weight_text"] * text_ratio
                 + policy["step_ungrounded_fact"] * n_facts
                 + policy["step_conflict"] * len(conflicts))
        score = round(float(min(1.0, max(0.0, score))), 3)

        evidence = {
            "hallucination_score": score,
            "unsupported_ratio": round(text_ratio, 3),
            "ungrounded_numbers": bad_numbers,
            "ungrounded_names": bad_names,
            "ungrounded_fact_count": n_facts,
            "conflicts": conflicts,
        }

        if score >= policy["block_threshold"]:
            status, reason = "block", f"High hallucination likelihood ({score})."
        elif score >= policy["warn_threshold"]:
            status, reason = "warn", f"Possible hallucination ({score})."
        else:
            status, reason = "pass", f"Low hallucination likelihood ({score})."

        parts = []
        if text_ratio > 0:
            parts.append(f"{round(text_ratio * 100)}% of answer sentences unsupported")
        if bad_numbers or bad_names:
            parts.append("not found in the cited documents: " + ", ".join(bad_numbers + bad_names))
        if conflicts:
            parts.append(f"{len(conflicts)} sentence(s) contradict their source ({conflicts[0]['kind']})")
        if parts and status != "pass":
            reason = reason + " Details: " + "; ".join(parts) + "."
        return self._verdict(status, score, reason, evidence)