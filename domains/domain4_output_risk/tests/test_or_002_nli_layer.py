"""
Tests for the OPTIONAL NLI layer of QSAF-OR-002.

Run (PowerShell, repo root):
    python -m pytest domains/domain4_output_risk/tests/test_or_002_nli_layer.py -v

These tests use a FAKE verifier, so they need no model download, no internet and no
sentence-transformers package. They check our logic (claim selection, passage retrieval,
thresholds, fallback), not the quality of a real NLI model.
To try a real model once on your machine, see tests/try_real_nli.py.
"""

import copy
import json
from unittest.mock import patch

import pytest

from core.models import RequestContext
from core.policy_loader import load_domain_policy
from domains.domain4_output_risk.controls import or_002_hallucination_flag as m002
from domains.domain4_output_risk.controls.or_002_hallucination_flag import (
    HallucinationFlagOR002, checkable_claims, split_passages, to_probabilities,
)

DOCS = [{"content": "The Karakoram Highway was completed in 1979 and links Pakistan with China."}]
SUPPORTED_REPLY = "The Karakoram Highway was completed in 1979 and links Pakistan with China."
CONTRADICTED_REPLY = "The Karakoram Highway was completed in 1985 and links Pakistan with India."


def ctx(reply, docs=DOCS, prompt="Tell me about the highway"):
    return RequestContext(session_id="s", user_id="u", raw_prompt=prompt, agent_output=reply, retrieved_docs=docs)


def fake_verifier(entail=0.0, contra=0.0, record=None):
    def verify(pairs):
        if record is not None:
            record.extend(pairs)
        return [{"entailment": entail, "contradiction": contra, "neutral": max(0.0, 1.0 - entail - contra)} for _ in pairs]
    return verify


def nli_control(verifier, method="nli", nli_over=None, **grounding_over):
    """Return (control, policy_patch) with grounding.method set as requested."""
    cfg = copy.deepcopy(load_domain_policy("domain4_output_risk")["or_002_hallucination"])
    cfg["grounding"]["method"] = method
    cfg["grounding"].update(grounding_over)
    if nli_over:
        cfg["grounding"]["nli"].update(nli_over)
    return HallucinationFlagOR002(nli_verifier=verifier), patch.object(m002, "load_domain_policy", return_value={"or_002_hallucination": cfg})


# ------------------------------------------------------------------ default stays offline
def test_default_method_is_overlap_and_never_calls_the_verifier():
    calls = []
    control, patched = nli_control(fake_verifier(record=calls), method="overlap")
    with patched:
        v = control.safe_evaluate(ctx(SUPPORTED_REPLY))
    assert calls == [] and v.evidence["grounding_method_used"] == "overlap"


def test_shipped_policy_default_is_overlap():
    assert load_domain_policy("domain4_output_risk")["or_002_hallucination"]["grounding"]["method"] == "overlap"


# ------------------------------------------------------------------ NLI verdicts
def test_supported_claim_passes():
    control, patched = nli_control(fake_verifier(entail=0.95))
    with patched:
        v = control.safe_evaluate(ctx(SUPPORTED_REPLY))
    assert v.status == "pass"
    assert v.evidence["grounding_method_used"] == "nli" and v.evidence["claims_unsupported"] == 0


def test_contradicted_claim_warns_with_higher_cap():
    control, patched = nli_control(fake_verifier(entail=0.02, contra=0.95))
    with patched:
        v = control.safe_evaluate(ctx(CONTRADICTED_REPLY))
    cfg = load_domain_policy("domain4_output_risk")["or_002_hallucination"]
    assert v.status == "warn" and v.evidence["claims_contradicted"] == 1
    assert cfg["max_risk"] < v.risk_score <= cfg["grounding"]["nli"]["max_risk"]
    assert "contradicted" in v.reason


def test_neutral_claim_warns_but_stays_under_the_normal_cap():
    control, patched = nli_control(fake_verifier(entail=0.10, contra=0.10))
    with patched:
        v = control.safe_evaluate(ctx(CONTRADICTED_REPLY))
    cfg = load_domain_policy("domain4_output_risk")["or_002_hallucination"]
    assert v.status == "warn" and v.evidence["claims_contradicted"] == 0
    assert v.risk_score <= cfg["max_risk"]


def test_threshold_comes_from_policy():
    control, patched = nli_control(fake_verifier(entail=0.80), nli_over={"entail_threshold": 0.90})
    with patched:
        v = control.safe_evaluate(ctx(SUPPORTED_REPLY))
    assert v.status == "warn"          # 0.80 no longer counts as "supported"


def test_one_supporting_passage_beats_a_contradicting_one():
    docs = [{"content": "The Karakoram Highway was completed in 1979 and links Pakistan with China."},
            {"content": "Some blogs wrongly say the Karakoram Highway was completed in 1985 for India."}]

    def verify(pairs):
        return [{"entailment": 0.9 if "1979" in premise else 0.0,
                 "contradiction": 0.0 if "1979" in premise else 0.9, "neutral": 0.1} for premise, _ in pairs]

    control, patched = nli_control(verify)
    with patched:
        v = control.safe_evaluate(ctx(SUPPORTED_REPLY, docs=docs))
    assert v.status == "pass"


# ------------------------------------------------------------------ evidence retrieval
def test_claim_unrelated_to_documents_skips_the_model():
    calls = []
    control, patched = nli_control(fake_verifier(entail=0.9, record=calls))
    with patched:
        v = control.safe_evaluate(ctx("The Eiffel Tower was built in 1889 in Paris by Gustave Eiffel."))
    assert calls == []                 # nothing in the documents was even about it
    assert v.evidence["claims_unsupported"] == 1 and v.status == "warn"


def test_the_most_relevant_passage_is_the_premise():
    docs = [{"content": "Bananas are rich in potassium and grow in warm climates."},
            {"content": "The Karakoram Highway was completed in 1979 and links Pakistan with China."}]
    calls = []
    control, patched = nli_control(fake_verifier(entail=0.9, record=calls))
    with patched:
        control.safe_evaluate(ctx(SUPPORTED_REPLY, docs=docs))
    assert calls and all("Karakoram" in premise for premise, _ in calls)


def test_max_claims_limits_the_work():
    calls = []
    reply = " ".join(f"The Karakoram Highway carried {100 + i} trucks on day {i}." for i in range(1, 6))
    control, patched = nli_control(fake_verifier(entail=0.9, record=calls), nli_over={"max_claims": 2})
    with patched:
        v = control.safe_evaluate(ctx(reply))
    assert v.evidence["claims_checked"] == 2
    top_k = load_domain_policy("domain4_output_risk")["or_002_hallucination"]["grounding"]["nli"]["top_k_passages"]
    assert len(calls) <= 2 * top_k


def test_without_documents_the_model_is_not_used():
    calls = []
    control, patched = nli_control(fake_verifier(entail=0.9, record=calls))
    with patched:
        v = control.safe_evaluate(ctx(SUPPORTED_REPLY, docs=[]))
    assert calls == [] and v.evidence["mode"] == "weak_signals"


# ------------------------------------------------------------------ safe fallback
def test_verifier_error_falls_back_to_overlap_without_crashing():
    def broken(pairs):
        raise RuntimeError("model exploded")
    control, patched = nli_control(broken)
    with patched:
        v = control.safe_evaluate(ctx(SUPPORTED_REPLY))
    assert v.status == "pass"          # overlap finds the claim supported
    assert v.evidence["nli_fallback"] is True and v.evidence["grounding_method_used"] == "overlap"
    assert v.evidence["nli_error"] == "RuntimeError" and "unavailable" in v.reason


def test_missing_package_or_model_falls_back():
    control, patched = nli_control(None)          # no injected verifier: real loader is used
    with patched, patch.object(m002, "_build_default_verifier", side_effect=ImportError("no sentence_transformers")):
        v = control.safe_evaluate(ctx(CONTRADICTED_REPLY))
    assert v.evidence["nli_fallback"] is True and v.evidence["nli_error"] == "ImportError"
    assert v.evidence["grounding_method_used"] == "overlap"      # safe fallback, no crash


def test_overlap_misses_a_contradiction_that_nli_catches():
    """Why the NLI layer exists: the wrong year and country still share most words with the document."""
    control_overlap, patched_overlap = nli_control(fake_verifier(), method="overlap")
    with patched_overlap:
        by_overlap = control_overlap.safe_evaluate(ctx(CONTRADICTED_REPLY))
    control_nli, patched_nli = nli_control(fake_verifier(entail=0.02, contra=0.95))
    with patched_nli:
        by_nli = control_nli.safe_evaluate(ctx(CONTRADICTED_REPLY))
    assert by_overlap.status == "pass" and by_overlap.evidence["claims_contradicted"] == 0
    assert by_nli.status == "warn" and by_nli.evidence["claims_contradicted"] == 1


def test_wrong_number_of_results_falls_back():
    control, patched = nli_control(lambda pairs: [])
    with patched:
        v = control.safe_evaluate(ctx(SUPPORTED_REPLY))
    assert v.evidence["nli_fallback"] is True


def test_missing_nli_settings_fall_back():
    cfg = copy.deepcopy(load_domain_policy("domain4_output_risk")["or_002_hallucination"])
    cfg["grounding"]["method"] = "nli"
    del cfg["grounding"]["nli"]["model_name"]
    control = HallucinationFlagOR002(nli_verifier=fake_verifier(entail=0.9))
    with patch.object(m002, "load_domain_policy", return_value={"or_002_hallucination": cfg}):
        v = control.safe_evaluate(ctx(SUPPORTED_REPLY))
    assert v.evidence["nli_fallback"] is True


# ------------------------------------------------------------------ privacy
def test_evidence_and_reason_contain_no_reply_or_document_text():
    control, patched = nli_control(fake_verifier(contra=0.95))
    with patched:
        v = control.safe_evaluate(ctx(CONTRADICTED_REPLY))
    blob = (v.reason + json.dumps(v.evidence)).lower()
    for secret in ("karakoram", "1985", "india", "china"):
        assert secret not in blob


# ------------------------------------------------------------------ helper functions
def test_to_probabilities_handles_logits_and_probabilities():
    labels = ["contradiction", "entailment", "neutral"]
    from_logits = to_probabilities([[0.1, 4.0, 0.2]], labels)[0]
    assert abs(sum(from_logits.values()) - 1.0) < 1e-9 and from_logits["entailment"] > 0.9
    from_probs = to_probabilities([[0.1, 0.8, 0.1]], labels)[0]
    assert from_probs == {"contradiction": 0.1, "entailment": 0.8, "neutral": 0.1}


def test_to_probabilities_rejects_wrong_label_count():
    with pytest.raises(ValueError):
        to_probabilities([[0.1, 0.9]], ["contradiction", "entailment", "neutral"])


def test_checkable_claims_keeps_only_facts_with_numbers_or_names():
    reply = "That sounds good. The Karakoram Highway was completed in 1979. It is long and wide and nice."
    assert checkable_claims(reply, min_words=5) == ["The Karakoram Highway was completed in 1979."]


def test_split_passages_overlaps_long_documents_and_keeps_short_ones_whole():
    assert split_passages(["one two three"], max_words=10) == ["one two three"]
    long_doc = " ".join(f"w{i}" for i in range(30))
    passages = split_passages([long_doc], max_words=10)
    assert len(passages) >= 3 and all(len(p.split()) <= 10 for p in passages)
    assert set(passages[0].split()) & set(passages[1].split())      # windows overlap
