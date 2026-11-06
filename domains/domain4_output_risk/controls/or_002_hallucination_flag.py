"""
domains/domain4_output_risk/controls/or_002_hallucination_flag.py

QSAF-OR-002: Flag hallucinated facts in responses (real-time, egress).

Honest limit: no program can know the truth. So this control NEVER says
"hallucination proven". It only warns, using evidence it can actually see:

  A) WEAK SIGNALS (always on): URLs or emails nobody mentioned before, very
     precise statistics, "according to a study" with no source, citation-shaped
     text, overconfident wording.

  B) GROUNDING against ctx.retrieved_docs (only when documents exist). The reply is
     split into checkable claims (sentences with a number or a name). Each claim is
     compared with the documents by ONE of two methods chosen in policy.yaml:

        method: overlap   (default) word overlap. Fast, offline, no extra packages.
        method: nli       OPTIONAL stronger check. For each claim we pick the most
                          relevant passages from the documents, then a small NLI model
                          ("natural language inference") says whether the passage
                          ENTAILS the claim, CONTRADICTS it, or says nothing (neutral).

     If the NLI model cannot be loaded (no package, no internet, bad config) the control
     does NOT crash: it falls back to the overlap method and says so in the evidence.

Result is pass or warn only. Evidence holds counts and ids, never reply or document text.

Important: NLI checks agreement with the documents we were GIVEN. If those documents are
wrong, or the claim is not covered by them, the result says nothing about real-world truth.
"""

import math
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

# Loaded NLI models are kept here so the (slow) download/load happens once per process.
_NLI_MODELS: dict = {}


# ----------------------------------------------------------------- small helpers
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


def checkable_claims(reply: str, min_words: int) -> list:
    """Sentences worth checking: long enough AND containing a number or a name."""
    claims = []
    for sentence in _SENTENCE_SPLIT.split(reply):
        tokens = sentence.split()
        if len(tokens) < min_words:
            continue
        has_number = bool(re.search(r"\d", sentence))
        has_name = any(t[:1].isupper() and t[1:].islower() for t in tokens[1:])
        if has_number or has_name:
            claims.append(sentence)
    return claims


def split_passages(doc_texts: list, max_words: int) -> list:
    """Cut documents into overlapping windows of max_words words (the 'evidence' pieces)."""
    passages = []
    step = max(1, max_words // 2)
    for text in doc_texts:
        words = text.split()
        if not words:
            continue
        for start in range(0, len(words), step):
            passages.append(" ".join(words[start:start + max_words]))
            if start + max_words >= len(words):
                break
    return passages


# -------------------------------------------------------------------- NLI plumbing
def to_probabilities(raw_rows, label_order: list) -> list:
    """
    Turn a model's raw output into [{"contradiction": p, "entailment": p, "neutral": p}, ...].
    Accepts logits OR probabilities (different library versions return different things).
    """
    out = []
    for raw in raw_rows:
        row = [float(v) for v in raw]
        if len(row) != len(label_order):
            raise ValueError("NLI model returned an unexpected number of labels")
        already_probabilities = all(0.0 <= v <= 1.0 for v in row) and abs(sum(row) - 1.0) < 1e-3
        if not already_probabilities:
            peak = max(row)
            exps = [math.exp(v - peak) for v in row]
            total = sum(exps)
            row = [e / total for e in exps]
        out.append(dict(zip(label_order, row)))
    return out


def _build_default_verifier(model_name: str, label_order: list):
    """
    Create the real NLI verifier (a sentence-transformers CrossEncoder).
    Needs the sentence-transformers package and, the first time, internet to download the model.
    Raises if either is missing; the caller turns that into a safe fallback.
    """
    model = _NLI_MODELS.get(model_name)
    if model is None:
        from sentence_transformers import CrossEncoder  # imported here so the package stays optional
        model = CrossEncoder(model_name)
        _NLI_MODELS[model_name] = model

    def verify(pairs: list) -> list:
        return to_probabilities(model.predict(pairs), label_order)

    return verify


class HallucinationFlagOR002(Control):
    control_id = "OR-002"
    domain = "Domain 4: Output Risk & Response Control"
    layer = "egress"

    def __init__(self, nli_verifier=None):
        """
        nli_verifier: optional callable(list of (premise, claim)) -> list of
        {"entailment": p, "contradiction": p, "neutral": p}. Tests pass a fake one,
        so no model download is needed. Normally left as None.
        """
        super().__init__()
        self._injected_verifier = nli_verifier
        self._verifier_cache: dict = {}

    # ------------------------------------------------------------------ public
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

        # --- A) weak-signal patterns from policy
        matched_ids, invalid = [], []
        for sig in signals:
            try:
                if re.search(sig["pattern"], reply):
                    matched_ids.append(str(sig.get("id", "?")))
                    weights.append(float(sig.get("weight", 0.0)))
                    found.append(str(sig.get("category", "signal")).replace("_", " "))
            except (re.error, KeyError, TypeError, ValueError):
                invalid.append(str(sig.get("id", "?")) if isinstance(sig, dict) else "?")

        # --- A) URLs and emails nobody mentioned before
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

        # --- B) grounding against retrieved documents (only if we have some)
        mode = "weak_signals"
        method_requested = method_used = None
        claims_checked = claims_unsupported = claims_contradicted = 0
        nli_fallback = False
        nli_error = None
        risk_cap = max_risk
        if grounding.get("enabled", True) and any(t.strip() for t in doc_texts):
            mode = "grounded"
            try:
                min_words = int(grounding["min_claim_words"])
                min_claims = int(grounding["min_checkable_claims"])
                ratio_warn = float(grounding["unsupported_ratio_warn"])
                unsupported_weight = float(grounding["unsupported_weight"])
                method_requested = str(grounding.get("method", "overlap")).lower()
                claims = checkable_claims(reply, min_words)

                counts = None
                nli_cfg = grounding.get("nli", {}) or {}
                if method_requested == "nli" and claims:
                    try:
                        counts = self._verify_claims_nli(claims, doc_texts, stopwords, nli_cfg)
                        method_used = "nli"
                        claims_checked = counts["supported"] + counts["contradicted"] + counts["neutral"]
                        claims_contradicted = counts["contradicted"]
                        claims_unsupported = counts["contradicted"] + counts["neutral"]
                        if claims_contradicted:
                            weights.append(float(nli_cfg["contradiction_weight"]))
                            found.append(f"{claims_contradicted} claim(s) contradicted by the documents")
                            risk_cap = max(max_risk, float(nli_cfg["max_risk"]))
                    except Exception as exc:  # noqa: BLE001  model missing / no internet / bad config: fall back, never crash
                        nli_fallback = True
                        nli_error = type(exc).__name__
                        counts = None

                if counts is None:   # overlap method (the default, or the fallback)
                    method_used = "overlap"
                    support = float(grounding["support_overlap"])
                    doc_words = _content_words(" ".join(doc_texts), stopwords)
                    claims_checked = claims_unsupported = 0
                    for sentence in claims:
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
        score = round(min(1.0 - remaining, risk_cap), 3)
        status = "warn" if score >= warn_threshold else "pass"

        evidence = {
            "mode": mode,
            "grounding_method_requested": method_requested,
            "grounding_method_used": method_used,
            "matched_signal_ids": matched_ids,
            "unsourced_urls": len(unsourced_urls),
            "unsourced_emails": len(unsourced_emails),
            "claims_checked": claims_checked,
            "claims_unsupported": claims_unsupported,
            "claims_contradicted": claims_contradicted,
            "risk_cap": risk_cap,
        }
        if nli_fallback:
            evidence["nli_fallback"] = True
            evidence["nli_error"] = nli_error
        if invalid:
            evidence["invalid_rules"] = invalid

        note = " (NLI model unavailable, used the word-overlap check instead)" if nli_fallback else ""
        if status == "warn":
            reason = f"Possible unsupported facts: {', '.join(found)}. Weak evidence only, not proof of hallucination (risk {score:.2f}).{note}"
        elif found:
            reason = f"Minor signals only ({', '.join(found)}); below the warning level (risk {score:.2f}).{note}"
        else:
            reason = f"No hallucination warning signs found (risk 0.00).{note}"
        return self._verdict(status, score, reason, evidence)

    # ----------------------------------------------------------------- NLI layer
    def _get_verifier(self, model_name: str, label_order: list):
        if self._injected_verifier is not None:
            return self._injected_verifier
        key = (model_name, tuple(label_order))
        if key not in self._verifier_cache:
            self._verifier_cache[key] = _build_default_verifier(model_name, label_order)
        return self._verifier_cache[key]

    def _verify_claims_nli(self, claims: list, doc_texts: list, stopwords: set, nli: dict) -> dict:
        """
        For each claim: retrieve the most relevant passages (cheap word-overlap retrieval),
        run the NLI model on (passage, claim) pairs, and keep the best entailment and
        contradiction probabilities. Returns counts of supported / contradicted / neutral claims.
        """
        model_name = str(nli["model_name"])
        label_order = [str(x).lower() for x in nli["label_order"]]
        entail_threshold = float(nli["entail_threshold"])
        contradiction_threshold = float(nli["contradiction_threshold"])
        top_k = int(nli["top_k_passages"])
        passage_words = int(nli["passage_max_words"])
        max_claims = int(nli["max_claims"])
        float(nli["contradiction_weight"])   # validate early; used by the caller
        float(nli["max_risk"])

        verifier = self._get_verifier(model_name, label_order)
        passages = split_passages(doc_texts, passage_words)
        passage_vocab = [_content_words(p, stopwords) for p in passages]

        supported = contradicted = neutral = 0
        for claim in claims[:max_claims]:
            claim_vocab = _content_words(claim, stopwords)
            ranked = sorted(((len(claim_vocab & vocab), i) for i, vocab in enumerate(passage_vocab)), reverse=True)
            chosen = [passages[i] for score, i in ranked[:top_k] if score > 0]
            if not chosen:                 # nothing in the documents is even about this claim
                neutral += 1
                continue
            results = verifier([(passage, claim) for passage in chosen])
            if len(results) != len(chosen):
                raise ValueError("NLI verifier returned the wrong number of results")
            entail = max(float(r.get("entailment", 0.0)) for r in results)
            contra = max(float(r.get("contradiction", 0.0)) for r in results)
            if entail >= entail_threshold:
                supported += 1
            elif contra >= contradiction_threshold:
                contradicted += 1
            else:
                neutral += 1
        return {"supported": supported, "contradicted": contradicted, "neutral": neutral}

    def _verdict(self, status: str, score: float, reason: str, evidence: dict) -> Verdict:
        return Verdict(control_id=self.control_id, domain=self.domain, status=status,
                       risk_score=score, reason=reason, evidence=evidence)
