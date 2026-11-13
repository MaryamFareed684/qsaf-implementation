"""
SA-004: Flag mismatch between retrieval and output (Real-Time)
Domain: Domain 7: Source Attribution & RAG Monitoring

Checks that the retrieved documents are relevant to the user's question. If the best
question-to-document similarity is below the threshold, the retriever fetched the wrong
material, so even a faithful answer cannot be trusted (failure 6, bad retrieval, which
SA-002 and SA-003 cannot see because they only compare the answer with the documents).

If the answer is itself a refusal ("I could not find that in the documents") irrelevant
retrieval is the expected situation and the control passes.

Known limits: the model and threshold come from calibrate_domain7.py and depend on the
document collection; one irrelevant doc among relevant ones is tolerated.
"""

import numpy as np

from core.control_base import Control
from core.models import RequestContext, Verdict
from domains.domain7_source_attribution_rag import common
from domains.domain7_source_attribution_rag.controls.sa_002_response_vs_docs import _get_model


class RetrievalRelevanceSA004(Control):
    control_id = "SA-004"
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
        policy = full.get("retrieval_relevance")
        if not policy:
            return self._verdict("warn", 0.5, "Missing 'retrieval_relevance' section in policy.yaml.")
        if not policy.get("enabled", True):
            return self._verdict("pass", 0.0, "Retrieval relevance check disabled in policy.")

        question = (ctx.raw_prompt or "").strip()
        if not question:
            return self._verdict("pass", 0.0, "No question to compare against.")
        docs = [d for d in ctx.retrieved_docs if str(d.get("text", "")).strip()]
        if not docs:
            return self._verdict("pass", 0.0, "No retrieved documents; relevance cannot be assessed (SA-002 covers this).")

        answer = (ctx.agent_output or "").strip()
        if answer:
            sentences = common.split_sentences(common.strip_citations(answer, common.citation_pattern(full)))
            refusal_policy = full.get("refusal")
            if sentences and all(common.is_refusal_sentence(s, refusal_policy) for s in sentences):
                return self._verdict(
                    "pass", 0.0,
                    "Answer declines to answer, so irrelevant retrieval is the expected situation.",
                    {"refusal": True},
                )

        try:
            model = _get_model(policy["model_name"])
            emb = model.encode([question] + [str(d["text"]) for d in docs], normalize_embeddings=True)
        except Exception as exc:
            return self._verdict("warn", 0.5, f"Could not compute embeddings: {exc}")

        sims = emb[1:] @ emb[0]
        threshold = float(policy["relevance_threshold"])
        per_doc = [
            {"doc_id": d.get("doc_id", "unknown"),
             "similarity": round(float(s), 3),
             "relevant": bool(s >= threshold)}
            for d, s in zip(docs, sims)
        ]
        best_i = int(np.argmax(sims))
        best = float(sims[best_i])
        evidence = {
            "best_similarity": round(best, 3),
            "best_doc_id": per_doc[best_i]["doc_id"],
            "threshold": threshold,
            "model_name": policy["model_name"],
            "docs": per_doc,
        }

        if best >= threshold:
            return self._verdict(
                "pass", 0.0,
                f"At least one retrieved document is relevant to the question (best {round(best, 3)}).",
                evidence,
            )

        shortfall = 1.0 - max(best, 0.0) / threshold
        risk = round(float(min(1.0, policy["warn_risk_base"] + policy["warn_risk_scale"] * shortfall)), 3)
        return self._verdict(
            "warn", risk,
            f"No retrieved document is relevant to the question (best similarity {round(best, 3)}).",
            evidence,
        )