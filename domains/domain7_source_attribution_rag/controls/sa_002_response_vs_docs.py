"""
SA-002: Compare LLM response to top-K retrieved docs (Real-Time)
Domain: Domain 7: Source Attribution & RAG Monitoring

Splits the answer into sentences (citation markers removed) and embeds them together
with the retrieved document sentences. A sentence is "supported" when its best cosine
similarity to a document sentence reaches the threshold, OR when enough of its content
words appear in that document (lexical fallback for short answers).
Refusal sentences ("I could not find that in the documents") make no claim and are skipped.

Known limits (measured): embeddings capture topic, not agreement of facts, so a wrong
number or a negation still scores high. SA-003 covers those cases.
"""

import numpy as np

from core.control_base import Control
from core.models import RequestContext, Verdict
from domains.domain7_source_attribution_rag import common

_models: dict = {}  # model name -> loaded model (lazy: loaded on first use, not at import)


def _get_model(name: str):
    if name not in _models:
        from sentence_transformers import SentenceTransformer
        _models[name] = SentenceTransformer(name)
    return _models[name]


class ResponseVsDocsSA002(Control):
    control_id = "SA-002"
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
        policy = full.get("response_vs_docs")
        if not policy:
            return self._verdict("warn", 0.5, "Missing 'response_vs_docs' section in policy.yaml.")
        if not policy.get("enabled", True):
            return self._verdict("pass", 0.0, "Response-vs-docs check disabled in policy.")

        answer = (ctx.agent_output or "").strip()
        if not answer:
            return self._verdict("pass", 0.0, "No agent output to check.",
                                 {"unsupported_ratio": 0.0, "sentences": []})

        sentences = common.split_sentences(common.strip_citations(answer, common.citation_pattern(full)))
        refusal_policy = full.get("refusal")
        refusals = [s for s in sentences if common.is_refusal_sentence(s, refusal_policy)]
        claims = [s for s in sentences
                  if s not in refusals and len(s.split()) >= int(policy["min_words"])]
        if not claims:
            if refusals:
                return self._verdict(
                    "pass", 0.0, "Answer declines to answer; there are no factual claims to verify.",
                    {"unsupported_ratio": 0.0, "refusal": True, "sentences": []})
            return self._verdict("pass", 0.0, "No checkable sentences in the answer.",
                                 {"unsupported_ratio": 0.0, "sentences": []})

        docs = [d for d in ctx.retrieved_docs if str(d.get("text", "")).strip()]
        if not docs:
            return self._verdict(
                "warn", float(policy["no_docs_risk"]),
                "Answer produced but no documents were retrieved, so it cannot be verified.",
                {"unsupported_ratio": 1.0, "sentences": []},
            )

        doc_sents, doc_ids, doc_index = [], [], []
        for i, doc in enumerate(docs):
            for s in common.split_sentences(str(doc["text"])):
                doc_sents.append(s)
                doc_ids.append(doc.get("doc_id", "unknown"))
                doc_index.append(i)

        try:
            model = _get_model(policy["model_name"])
            doc_emb = model.encode(doc_sents, normalize_embeddings=True)
            ans_emb = model.encode(claims, normalize_embeddings=True)
        except Exception as exc:  # model missing, no network, etc.
            return self._verdict("warn", 0.5, f"Could not compute embeddings: {exc}")

        sims = ans_emb @ doc_emb.T
        threshold = float(policy["support_threshold"])
        lexical_threshold = float(policy["lexical_support"])
        details, unsupported = [], 0
        for sent, row in zip(claims, sims):
            j = int(np.argmax(row))
            score = float(row[j])
            coverage = common.lexical_coverage(sent, str(docs[doc_index[j]]["text"]))
            ok = score >= threshold or coverage >= lexical_threshold
            if not ok:
                unsupported += 1
            details.append({
                "text": sent[:200],
                "max_similarity": round(score, 3),
                "lexical_coverage": round(float(coverage), 3),
                "best_doc_id": doc_ids[j],
                "best_doc_sentence": doc_sents[j][:200],
                "supported": bool(ok),
            })

        ratio = unsupported / len(claims)
        evidence = {
            "unsupported_ratio": round(float(ratio), 3),
            "threshold": threshold,
            "refusal": bool(refusals),
            "sentences": details,
        }
        if unsupported == 0:
            return self._verdict(
                "pass", 0.0,
                f"All {len(claims)} answer sentence(s) are supported by retrieved documents.",
                evidence,
            )

        risk = round(float(min(1.0, policy["warn_risk_base"] + policy["warn_risk_scale"] * ratio)), 3)
        status = "block" if ratio >= policy["block_ratio"] else "warn"
        return self._verdict(
            status, risk,
            f"{unsupported} of {len(claims)} answer sentence(s) are not supported by the retrieved documents.",
            evidence,
        )