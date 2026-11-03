"""
SA-002: Compare LLM response to top-K retrieved docs (Real-Time)
Domain: Domain 7: Source Attribution & RAG Monitoring

Splits the answer into sentences and embeds them together with the retrieved
document sentences. A sentence whose best cosine similarity to any document
sentence is below the threshold is "unsupported".

Known limitation (measured): embeddings capture topic, not agreement of facts,
so a wrong number ("30 days" vs "14 days") still scores high. SA-003 covers that.
"""

import re

import numpy as np

from core.control_base import Control
from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy

DOMAIN_FOLDER = "domain7_source_attribution_rag"

_model = None  # lazy: the model loads on first use, not at import


def _get_model(name: str):
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer
        _model = SentenceTransformer(name)
    return _model


def split_sentences(text: str) -> list[str]:
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+", text) if s.strip()]


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
        policy = load_domain_policy(DOMAIN_FOLDER).get("response_vs_docs")
        if not policy:
            return self._verdict("warn", 0.5, "Missing 'response_vs_docs' section in policy.yaml.")
        if not policy.get("enabled", True):
            return self._verdict("pass", 0.0, "Response-vs-docs check disabled in policy.")

        answer = (ctx.agent_output or "").strip()
        if not answer:
            return self._verdict("pass", 0.0, "No agent output to check.")

        if not ctx.retrieved_docs:
            return self._verdict(
                "warn", float(policy["no_docs_risk"]),
                "Answer produced but no documents were retrieved, so it cannot be verified.",
                {"unsupported_ratio": 1.0, "sentences": []},
            )

        answer_sents = [s for s in split_sentences(answer)
                        if len(s.split()) >= policy["min_words"]]
        if not answer_sents:
            return self._verdict("pass", 0.0, "No checkable sentences in the answer.")

        doc_sents, doc_ids = [], []
        for doc in ctx.retrieved_docs:
            for s in split_sentences(str(doc.get("text", ""))):
                doc_sents.append(s)
                doc_ids.append(doc.get("doc_id", "unknown"))
        if not doc_sents:
            return self._verdict("warn", float(policy["no_docs_risk"]),
                                 "Retrieved documents contain no text to compare against.")

        try:
            model = _get_model(policy["model_name"])
            doc_emb = model.encode(doc_sents, normalize_embeddings=True)
            ans_emb = model.encode(answer_sents, normalize_embeddings=True)
        except Exception as exc:  # model missing, no network, etc.
            return self._verdict("warn", 0.5, f"Could not compute embeddings: {exc}")

        sims = ans_emb @ doc_emb.T
        threshold = float(policy["support_threshold"])
        details = []
        unsupported = 0
        for sent, row in zip(answer_sents, sims):
            j = int(np.argmax(row))
            score = float(row[j])
            ok = score >= threshold
            if not ok:
                unsupported += 1
            details.append({
                "text": sent[:200],
                "max_similarity": round(score, 3),
                "best_doc_id": doc_ids[j],
                "supported": bool(ok),
            })

        ratio = unsupported / len(answer_sents)
        evidence = {
            "unsupported_ratio": round(float(ratio), 3),
            "threshold": threshold,
            "sentences": details,
        }

        if unsupported == 0:
            return self._verdict(
                "pass", 0.0,
                f"All {len(answer_sents)} answer sentence(s) are supported by retrieved documents.",
                evidence,
            )

        risk = round(float(min(1.0, policy["warn_risk_base"] + policy["warn_risk_scale"] * ratio)), 3)
        status = "block" if ratio >= policy["block_ratio"] else "warn"
        return self._verdict(
            status, risk,
            f"{unsupported} of {len(answer_sents)} answer sentence(s) are not supported by the retrieved documents.",
            evidence,
        )