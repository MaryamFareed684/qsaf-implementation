"""
SA-006: Embed source trust rating into response (Auditable)
Domain: Domain 7: Source Attribution & RAG Monitoring

Looks up a trust level for every source the answer relies on (the documents it
cites, or all retrieved documents if it cites nothing). The verdict follows the
LEAST trusted source. A control may not mutate ctx, so the "embedding" is a
ready-made trust_footer string in Verdict.evidence for the caller to append.

When the answer cites nothing we cannot know which document it used, so a block
is capped to warn.

Covers failure 5 (poisoned or low-trust document), which SA-002 and SA-003
cannot see: an answer faithful to a bad source still looks "supported".
"""

import re

from core.control_base import Control
from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy

DOMAIN_FOLDER = "domain7_source_attribution_rag"


class SourceTrustSA006(Control):
    control_id = "SA-006"
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
        full = load_domain_policy(DOMAIN_FOLDER)
        policy = full.get("source_trust")
        if not policy:
            return self._verdict("warn", 0.5, "Missing 'source_trust' section in policy.yaml.")
        if not policy.get("enabled", True):
            return self._verdict("pass", 0.0, "Source trust check disabled in policy.")

        answer = (ctx.agent_output or "").strip()
        if not answer:
            return self._verdict("pass", 0.0, "No agent output to annotate.")
        if not ctx.retrieved_docs:
            return self._verdict("pass", 0.0, "No retrieved documents to rate.")

        pattern = (full.get("attribution") or {}).get("citation_pattern", r"\[([A-Za-z0-9_.-]+)\]")
        cited = set(re.findall(pattern, answer))
        cited_docs = [d for d in ctx.retrieved_docs if str(d.get("doc_id", "")) in cited]
        if cited_docs:
            relied, reliance = cited_docs, "cited"
        else:
            relied, reliance = list(ctx.retrieved_docs), "all_retrieved"

        level_risk = policy["level_risk"]
        rated = []
        for d in relied:
            source = str(d.get("source", "unknown"))
            level = policy["sources"].get(source, policy["default_level"])
            if level not in level_risk:
                return self._verdict("warn", 0.5, f"Unknown trust level '{level}' for source '{source}'.")
            rated.append({"doc_id": d.get("doc_id", "unknown"), "source": source, "trust": level})

        worst = max(rated, key=lambda r: level_risk[r["trust"]])
        status = policy["level_status"][worst["trust"]]
        if reliance == "all_retrieved" and status == "block":
            status = "warn"
        risk = round(float(level_risk[worst["trust"]]), 3)

        footer = "Sources: " + ", ".join(f"{r['source']} (trust: {r['trust']})" for r in rated)
        evidence = {
            "reliance": reliance,
            "rated_sources": rated,
            "lowest_trust": worst["trust"],
            "trust_footer": footer,
        }
        reason = (f"Answer relies on {len(rated)} source(s); lowest trust is "
                  f"'{worst['trust']}' ({worst['source']}).")
        return self._verdict(status, risk, reason, evidence)