"""
SA-005: Log and alert for non-attributable responses (Auditable)
Domain: Domain 7: Source Attribution & RAG Monitoring

An answer is attributable when it cites its sources AND every cited id belongs to a
document that was actually retrieved.
  - citation to a missing source  -> block (fabricated attribution)
  - no citation at all            -> warn  (answer cannot be traced)
  - a pure refusal makes no claim -> no citation needed

The audit trail is the Verdict itself: cited, valid and invalid ids go into evidence,
which the shared logger writes to the audit log.

Known limit: any bracketed token matching the pattern (for example a numeric footnote
like [1]) counts as a citation.
"""

import re

from core.control_base import Control
from core.models import RequestContext, Verdict
from domains.domain7_source_attribution_rag import common


class NonAttributableLogSA005(Control):
    control_id = "SA-005"
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
        full = common.load_policy()
        policy = full.get("attribution")
        if not policy:
            return self._verdict("warn", 0.5, "Missing 'attribution' section in policy.yaml.")
        if not policy.get("enabled", True):
            return self._verdict("pass", 0.0, "Attribution check disabled in policy.")

        answer = (ctx.agent_output or "").strip()
        if not answer:
            return self._verdict("pass", 0.0, "No agent output to attribute.")

        pattern = policy["citation_pattern"]
        retrieved_ids = [str(d.get("doc_id", "")) for d in ctx.retrieved_docs if d.get("doc_id")]
        cited = list(dict.fromkeys(re.findall(pattern, answer)))  # unique, ordered
        valid = [c for c in cited if c in retrieved_ids]
        invalid = [c for c in cited if c not in retrieved_ids]
        evidence = {
            "cited_ids": cited,
            "valid_ids": valid,
            "invalid_ids": invalid,
            "retrieved_ids": retrieved_ids,
        }

        if invalid:
            return self._verdict(
                "block", float(policy["invalid_citation_risk"]),
                f"Answer cites {len(invalid)} source(s) that were not retrieved: {', '.join(invalid)}.",
                evidence,
            )
        if not cited:
            sentences = common.split_sentences(common.strip_citations(answer, pattern))
            refusal_policy = full.get("refusal")
            if sentences and all(common.is_refusal_sentence(s, refusal_policy) for s in sentences):
                return self._verdict("pass", 0.0, "Answer declines to answer; no claim needs a source.", evidence)
            if policy.get("require_citations", True):
                return self._verdict(
                    "warn", float(policy["no_citation_risk"]),
                    "Answer has no source citation, so it cannot be attributed.",
                    evidence,
                )
            return self._verdict("pass", 0.0, "No citations, but citations are not required by policy.", evidence)

        return self._verdict("pass", 0.0, f"Answer cites {len(valid)} retrieved source(s).", evidence)