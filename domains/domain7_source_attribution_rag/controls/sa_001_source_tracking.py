"""
SA-001: Track document source in RAG systems (Auditable)
Domain: Domain 7: Source Attribution & RAG Monitoring

Checks that every retrieved document carries the fields needed to trace it
(doc_id and source), and puts the list of sources into Verdict.evidence so the
shared logger records it in the audit log.
"""

from core.control_base import Control
from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy

DOMAIN_FOLDER = "domain7_source_attribution_rag"


class SourceTrackingSA001(Control):
    control_id = "SA-001"
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
        policy = load_domain_policy(DOMAIN_FOLDER).get("source_tracking")
        if not policy:
            return self._verdict("warn", 0.5, "Missing 'source_tracking' section in policy.yaml.")
        if not policy.get("enabled", True):
            return self._verdict("pass", 0.0, "Source tracking disabled in policy.")

        docs = ctx.retrieved_docs
        if not docs:
            return self._verdict("pass", 0.0, "No retrieved documents to track.",
                                 {"tracked_sources": []})

        required = policy["required_fields"]
        tracked = []
        incomplete = []
        for i, doc in enumerate(docs):
            missing = [f for f in required if not str(doc.get(f, "")).strip()]
            if missing:
                incomplete.append({"position": i, "missing": missing})
            else:
                tracked.append({"doc_id": doc["doc_id"], "source": doc["source"]})

        if not incomplete:
            return self._verdict(
                "pass", 0.0,
                f"All {len(docs)} retrieved document(s) have a traceable source.",
                {"tracked_sources": tracked},
            )

        risk = min(1.0, policy["warn_risk_base"] + policy["warn_risk_per_missing"] * len(incomplete))
        return self._verdict(
            "warn", round(float(risk), 3),
            f"{len(incomplete)} of {len(docs)} retrieved document(s) lack a traceable source.",
            {"tracked_sources": tracked, "incomplete_docs": incomplete},
        )