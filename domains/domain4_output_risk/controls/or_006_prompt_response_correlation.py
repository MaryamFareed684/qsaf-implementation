"""
domains/domain4_output_risk/controls/or_006_prompt_response_correlation.py

QSAF-OR-006: Prompt-response correlation analysis (hybrid, egress).

What it does, in plain words: it asks "does the reply actually answer the prompt?" using
one of three methods chosen in policy.yaml (method:):

  keyword   (default) Counts how many of the prompt's key words appear in the reply
            (stop words removed, simple stemming). Fast, offline, no extra packages.
  embedding Turns prompt and reply into meaning-vectors with a sentence-transformers model and
            measures their cosine similarity. Understands paraphrases: "How do I fix a flat
            tyre?" and "Remove the wheel and patch the inner tube" share no words but are related.
  hybrid    The reply counts as on-topic if EITHER signal says so. This is the best at avoiding
            false alarms, because a paraphrase passes on meaning and an exact-word answer passes
            on words.

If the embedding model cannot load (no package, no internet), the control does NOT crash:
it falls back to the keyword method and records that in the evidence.

"Hybrid" also means the numbers (coverage, similarity) are stored in the evidence so they can be
analysed later in batch. Very short replies and refusals are skipped. The result is only ever a
warning with a capped risk. Evidence holds numbers only, never the prompt or reply words.
"""

import math
import re

from core.control_base import Control
from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy

POLICY_FOLDER = "domain4_output_risk"
POLICY_KEY = "or_006_prompt_response"

_WORD = re.compile(r"[a-z0-9]+")
_ENCODERS: dict = {}


def _stem(word: str) -> str:
    for suffix in ("ing", "ed", "es", "s"):
        if len(word) > len(suffix) + 3 and word.endswith(suffix):
            return word[: -len(suffix)]
    return word


def _keywords(text: str, stopwords: set) -> set:
    return {_stem(w) for w in _WORD.findall(text.lower()) if len(w) >= 3 and w not in stopwords}


def cosine_similarity(a, b) -> float:
    """Cosine of the angle between two vectors: 1 = same direction (same meaning), 0 = unrelated."""
    dot = sum(float(x) * float(y) for x, y in zip(a, b))
    norm_a = math.sqrt(sum(float(x) ** 2 for x in a))
    norm_b = math.sqrt(sum(float(y) ** 2 for y in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


def _build_default_encoder(model_name: str):
    """Create the real embedding encoder (sentence-transformers). Needs the package and, the first time, internet."""
    model = _ENCODERS.get(model_name)
    if model is None:
        from sentence_transformers import SentenceTransformer  # imported here so loading stays optional
        model = SentenceTransformer(model_name)
        _ENCODERS[model_name] = model

    def encode(texts: list) -> list:
        return [list(map(float, row)) for row in model.encode(texts)]

    return encode


class PromptResponseCorrelationOR006(Control):
    control_id = "OR-006"
    domain = "Domain 4: Output Risk & Response Control"
    layer = "egress"

    def __init__(self, encoder=None):
        """encoder: optional callable(list of texts) -> list of vectors. Tests pass a fake one."""
        super().__init__()
        self._injected_encoder = encoder
        self._encoder_cache: dict = {}

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
            method = str(cfg.get("method", "keyword")).lower()
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

        # --- keyword signal
        matched = len(prompt_keys & _keywords(reply, stopwords))
        coverage = matched / len(prompt_keys)
        keyword_risk = 0.0 if coverage >= ok_overlap else max_risk * (ok_overlap - coverage) / ok_overlap
        risk = keyword_risk

        # --- optional embedding signal
        similarity = None
        method_used = "keyword"
        embedding_fallback = False
        embedding_error = None
        if method in ("embedding", "hybrid"):
            try:
                emb = cfg["embedding"]
                ok_similarity = float(emb["ok_similarity"])
                max_chars = int(emb["max_chars"])
                encoder = self._get_encoder(str(emb["model_name"]))
                vectors = encoder([prompt[:max_chars], reply[:max_chars]])
                if len(vectors) != 2:
                    raise ValueError("encoder returned the wrong number of vectors")
                similarity = cosine_similarity(vectors[0], vectors[1])
                shortfall = max(ok_similarity - max(similarity, 0.0), 0.0)
                embedding_risk = 0.0 if similarity >= ok_similarity else max_risk * shortfall / ok_similarity
                risk = embedding_risk if method == "embedding" else min(keyword_risk, embedding_risk)
                method_used = method
            except Exception as exc:  # noqa: BLE001  package/model missing or bad settings: use keywords only
                embedding_fallback = True
                embedding_error = type(exc).__name__
                similarity = None

        risk = round(min(max(risk, 0.0), 1.0), 3)
        status = "warn" if risk >= warn_threshold else "pass"

        evidence = {
            "method_requested": method,
            "method_used": method_used,
            "prompt_keywords": len(prompt_keys),
            "matched_keywords": matched,
            "coverage": round(coverage, 3),
            "ok_overlap": ok_overlap,
            "similarity": None if similarity is None else round(similarity, 3),
            "reply_words": reply_words,
        }
        if embedding_fallback:
            evidence["embedding_fallback"] = True
            evidence["embedding_error"] = embedding_error

        sim_text = "" if similarity is None else f", meaning similarity {similarity:.2f}"
        note = " (embedding model unavailable, used keywords only)" if embedding_fallback else ""
        if status == "warn":
            reason = (f"Reply may not answer the question: {matched} of {len(prompt_keys)} key prompt words appear in it "
                      f"(coverage {coverage:.2f}{sim_text}, risk {risk:.2f}).{note}")
        else:
            reason = f"Reply is related to the prompt ({matched} of {len(prompt_keys)} key words covered, coverage {coverage:.2f}{sim_text}).{note}"
        return self._verdict(status, risk, reason, evidence)

    def _get_encoder(self, model_name: str):
        if self._injected_encoder is not None:
            return self._injected_encoder
        if model_name not in self._encoder_cache:
            self._encoder_cache[model_name] = _build_default_encoder(model_name)
        return self._encoder_cache[model_name]

    def _verdict(self, status: str, score: float, reason: str, evidence: dict) -> Verdict:
        return Verdict(control_id=self.control_id, domain=self.domain, status=status,
                       risk_score=score, reason=reason, evidence=evidence)
