"""
Tests for the Domain 4 IMPROVEMENTS:
  OR-003 token watermark detection | OR-004 NER | OR-005 decision engine (mandatory rules)
  OR-006 embeddings                | OR-007 emotion classifier

Run (PowerShell, repo root):
    python -m pytest domains/domain4_output_risk/tests/test_domain4_improvements.py -v

Offline: every model is replaced by a FAKE, so no downloads, no internet and no extra packages.
These tests check our logic (settings, scoring, fallback, privacy), not the quality of real models.
To try the real models once, run tests/try_real_models.py on your machine.
"""

import copy
import json
import os
import random
from unittest.mock import patch

import pytest

from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy
from domains.domain4_output_risk.controls import or_003_output_watermark as m003
from domains.domain4_output_risk.controls import or_004_sensitivity_scoring as m004
from domains.domain4_output_risk.controls import or_005_risky_reroute as m005
from domains.domain4_output_risk.controls import or_006_prompt_response_correlation as m006
from domains.domain4_output_risk.controls import or_007_tone_deviation as m007
from domains.domain4_output_risk.controls.or_003_output_watermark import (
    OutputWatermarkOR003, bias_logits, detect_token_watermark, is_green,
)
from domains.domain4_output_risk.controls.or_004_sensitivity_scoring import SensitivityScoringOR004, mask_value
from domains.domain4_output_risk.controls.or_005_risky_reroute import RiskyRerouteOR005, rule_matches
from domains.domain4_output_risk.controls.or_006_prompt_response_correlation import (
    PromptResponseCorrelationOR006, cosine_similarity,
)
from domains.domain4_output_risk.controls.or_007_tone_deviation import ToneDeviationOR007


def ctx(reply, prompt="test prompt", **kw):
    return RequestContext(session_id="s-test", user_id="u-test", raw_prompt=prompt, agent_output=reply, **kw)


def policy(key, **top):
    cfg = copy.deepcopy(load_domain_policy("domain4_output_risk")[key])
    cfg.update(top)
    return cfg


def patch_policy(module, key, cfg):
    return patch.object(module, "load_domain_policy", return_value={key: cfg})


# ===================================================================== OR-003 token watermark
WM_KEY = "unit-test-secret"
VOCAB = 300


def make_tokens(n, key, gamma, green_bias, seed=1):
    """Simulate a model: each step picks a green token with probability green_bias, else any token."""
    rng = random.Random(seed)
    tokens = [rng.randrange(VOCAB)]
    for _ in range(n):
        prev = tokens[-1]
        if rng.random() < green_bias:
            candidates = [t for t in range(VOCAB) if is_green(key, prev, t, gamma)]
            tokens.append(rng.choice(candidates))
        else:
            tokens.append(rng.randrange(VOCAB))
    return tokens


def test_003_green_share_is_close_to_gamma():
    share = sum(is_green(WM_KEY, 7, t, 0.25) for t in range(2000)) / 2000
    assert 0.20 < share < 0.30


def test_003_watermarked_text_is_detected_and_plain_text_is_not():
    marked = detect_token_watermark(make_tokens(120, WM_KEY, 0.25, 0.9), WM_KEY, 0.25, 4.0, 25)
    plain = detect_token_watermark(make_tokens(120, WM_KEY, 0.25, 0.0, seed=2), WM_KEY, 0.25, 4.0, 25)
    assert marked["detected"] is True and marked["z_score"] > 4.0
    assert plain["detected"] is False


def test_003_wrong_key_does_not_detect():
    tokens = make_tokens(120, WM_KEY, 0.25, 0.9)
    assert detect_token_watermark(tokens, "some-other-key", 0.25, 4.0, 25)["detected"] is False


def test_003_short_text_is_not_judged():
    result = detect_token_watermark([1, 2, 3, 4], WM_KEY, 0.25, 4.0, 25)
    assert result["detected"] is False and result["note"] == "too_short"


def test_003_bias_logits_raises_only_green_tokens():
    logits = [0.0] * 50
    biased = bias_logits(logits, 3, WM_KEY, 0.25, 2.0)
    for token, value in enumerate(biased):
        assert value == (2.0 if is_green(WM_KEY, 3, token, 0.25) else 0.0)


def test_003_token_watermark_is_off_by_default():
    v = OutputWatermarkOR003().safe_evaluate(ctx("A normal reply here.", metadata={"domain4_token_ids": [1, 2, 3]}))
    assert "token_watermark" not in v.evidence


def test_003_control_reports_detection_when_enabled():
    cfg = policy("or_003_watermark")
    cfg["token_watermark"]["enabled"] = True
    tokens = make_tokens(120, WM_KEY, cfg["token_watermark"]["gamma"], 0.9)
    with patch_policy(m003, "or_003_watermark", cfg), patch.dict(os.environ, {cfg["token_watermark"]["key_env_var"]: WM_KEY}):
        v = OutputWatermarkOR003().safe_evaluate(ctx("Some generated reply.", metadata={"domain4_token_ids": tokens}))
    assert v.status == "pass" and v.evidence["token_watermark"]["detected"] is True
    assert "watermark detected" in v.reason and "fingerprint" in v.evidence


@pytest.mark.parametrize("metadata,expected", [
    ({}, "not available"),
    ({"domain4_token_ids": "not a list"}, "invalid"),
])
def test_003_missing_or_invalid_token_ids_are_reported_not_crashed(metadata, expected):
    cfg = policy("or_003_watermark")
    cfg["token_watermark"]["enabled"] = True
    with patch_policy(m003, "or_003_watermark", cfg), patch.dict(os.environ, {cfg["token_watermark"]["key_env_var"]: WM_KEY}):
        v = OutputWatermarkOR003().safe_evaluate(ctx("Some reply.", metadata=metadata))
    assert expected in v.evidence["token_watermark"]["status"] and v.status == "pass"


def test_003_missing_token_key_is_reported():
    cfg = policy("or_003_watermark")
    cfg["token_watermark"]["enabled"] = True
    env = {k: v for k, v in os.environ.items() if k != cfg["token_watermark"]["key_env_var"]}
    with patch_policy(m003, "or_003_watermark", cfg), patch.dict(os.environ, env, clear=True):
        v = OutputWatermarkOR003().safe_evaluate(ctx("Some reply.", metadata={"domain4_token_ids": list(range(60))}))
    assert "not set" in v.evidence["token_watermark"]["status"]


def test_003_fingerprint_limit_is_documented_in_the_module():
    assert "does NOT prove an AI wrote" in m003.__doc__


# ===================================================================== OR-004 NER
def fake_ner(*items):
    """items: (entity_type, text_to_find, score). Returns spans located in the analysed text."""
    def analyze(text, entities):
        found = []
        for entity_type, snippet, score in items:
            start = text.find(snippet)
            if start >= 0 and entity_type in entities:
                found.append({"entity_type": entity_type, "start": start, "end": start + len(snippet), "score": score})
        return found
    return analyze


def ner_control(analyzer, **ner_over):
    cfg = policy("or_004_sensitivity")
    cfg["ner"]["enabled"] = True
    cfg["ner"].update(ner_over)
    return SensitivityScoringOR004(ner_analyzer=analyzer), patch_policy(m004, "or_004_sensitivity", cfg)


def test_004_ner_is_off_by_default():
    calls = []
    control = SensitivityScoringOR004(ner_analyzer=lambda t, e: calls.append(1) or [])
    v = control.safe_evaluate(ctx("Alice Johnson lives in Lahore."))
    assert calls == [] and "ner" not in v.evidence


def test_004_one_name_alone_is_low_risk_but_is_recorded():
    control, patched = ner_control(fake_ner(("PERSON", "Alice Johnson", 0.95)))
    with patched:
        v = control.safe_evaluate(ctx("Alice Johnson will call you back."))
    person = [f for f in v.evidence["findings"] if f["category"] == "person_name"]
    assert v.status == "pass" and person and person[0]["masked_samples"] == ["A***"]


def test_004_several_names_and_places_add_up_to_a_warning():
    control, patched = ner_control(fake_ner(("PERSON", "Alice Johnson", 0.9), ("PERSON", "Bilal Khan", 0.9), ("LOCATION", "Lahore", 0.9)))
    with patched:
        v = control.safe_evaluate(ctx("Alice Johnson and Bilal Khan live in Lahore."))
    assert v.status == "warn" and "person name" in v.reason


def test_004_name_plus_regex_data_raises_the_score():
    text = "Alice Johnson, card 4111 1111 1111 1111."
    plain = SensitivityScoringOR004().safe_evaluate(ctx(text))
    control, patched = ner_control(fake_ner(("PERSON", "Alice Johnson", 0.95)))
    with patched:
        with_ner = control.safe_evaluate(ctx(text))
    assert with_ner.risk_score > plain.risk_score


def test_004_low_confidence_entities_are_ignored():
    control, patched = ner_control(fake_ner(("PERSON", "Alice Johnson", 0.30)))
    with patched:
        v = control.safe_evaluate(ctx("Alice Johnson will call you back."))
    assert v.evidence["findings"] == []


def test_004_text_already_found_by_regex_is_not_counted_twice():
    control, patched = ner_control(fake_ner(("PERSON", "john.doe@example.com", 0.9)))
    with patched:
        v = control.safe_evaluate(ctx("Write to john.doe@example.com today."))
    assert [f["category"] for f in v.evidence["findings"]] == ["email"]


def test_004_ner_error_falls_back_to_regex_without_crashing():
    def broken(text, entities):
        raise RuntimeError("spaCy model missing")
    control, patched = ner_control(broken)
    with patched:
        v = control.safe_evaluate(ctx("Card 4111 1111 1111 1111 please."))
    assert v.status == "block" and v.evidence["ner"]["fallback"] is True and "NER unavailable" in v.reason


def test_004_missing_presidio_package_falls_back():
    cfg = policy("or_004_sensitivity")
    cfg["ner"]["enabled"] = True
    control = SensitivityScoringOR004()          # no injected analyzer: the real loader is used
    with patch_policy(m004, "or_004_sensitivity", cfg), patch.object(m004, "_build_default_analyzer", side_effect=ImportError("no presidio")):
        v = control.safe_evaluate(ctx("Alice Johnson is here."))
    assert v.evidence["ner"]["fallback"] is True and v.evidence["ner"]["error"] == "ImportError"


def test_004_ner_samples_are_masked_in_the_log():
    control, patched = ner_control(fake_ner(("PERSON", "Alice Johnson", 0.95), ("LOCATION", "Lahore", 0.95)))
    with patched:
        v = control.safe_evaluate(ctx("Alice Johnson lives in Lahore."))
    blob = v.reason + json.dumps(v.evidence)
    assert "Alice" not in blob and "Johnson" not in blob and "Lahore" not in blob


def test_004_mask_initial_style():
    assert mask_value("initial", "Alice Johnson") == "A***"


# ===================================================================== OR-005 decision engine
C005 = RiskyRerouteOR005()


def verdict(control_id, status, risk, **evidence):
    return Verdict(control_id, "d", status, risk, "r", evidence)


def test_005_rule_needs_every_condition_to_match():
    rule = {"control": "OR-004", "status_in": ["block"], "min_risk": 0.5}
    assert rule_matches(rule, verdict("OR-004", "block", 0.9))
    assert not rule_matches(rule, verdict("OR-001", "block", 0.9))      # wrong control
    assert not rule_matches(rule, verdict("OR-004", "warn", 0.9))       # wrong status
    assert not rule_matches(rule, verdict("OR-004", "block", 0.3))      # risk too low


def test_005_category_rule_reads_detector_evidence():
    rule = {"control": "OR-004", "category_in": ["api_key"]}
    assert rule_matches(rule, verdict("OR-004", "warn", 0.5, findings=[{"category": "api_key"}]))
    assert not rule_matches(rule, verdict("OR-004", "warn", 0.5, findings=[{"category": "email"}]))
    assert rule_matches({"control": "any", "category_in": ["weapons"]}, verdict("OR-001", "block", 0.9, categories=["weapons"]))


def test_005_secret_is_blocked_not_rerouted_by_a_mandatory_rule():
    v = C005.safe_evaluate(ctx("Use key sk_test_FAKE1234567890 to log in.", "How do I log in?"))
    assert v.evidence["action"] == "block"
    assert v.evidence["decided_by"] == "mandatory_rule:MR-03" and "MR-03" in v.evidence["fired_rules"]


def test_005_critical_risk_cannot_be_hidden_by_low_weights():
    """The whole point of mandatory rules: weights near zero must not let a private key through."""
    cfg = policy("or_005_risky_reroute", control_weights={"OR-001": 0.01, "OR-002": 0.01, "OR-004": 0.01, "OR-006": 0.01, "OR-007": 0.01})
    with patch_policy(m005, "or_005_risky_reroute", cfg):
        v = C005.safe_evaluate(ctx("-----BEGIN RSA PRIVATE KEY----- MIIB", "Show the file"))
    assert v.status == "block" and v.evidence["combined_risk"] < 0.1       # score says "fine", rule says "block"
    assert v.evidence["decided_by"].startswith("mandatory_rule")


def test_005_without_rules_the_weighted_score_still_decides():
    cfg = policy("or_005_risky_reroute", mandatory_rules=[], control_weights={"OR-001": 0.01, "OR-004": 0.01})
    with patch_policy(m005, "or_005_risky_reroute", cfg):
        v = C005.safe_evaluate(ctx("-----BEGIN RSA PRIVATE KEY----- MIIB", "Show the file"))
    assert v.evidence["decided_by"] == "weighted_score" and v.evidence["action"] != "block"


def test_005_more_severe_of_rule_and_score_wins():
    cfg = policy("or_005_risky_reroute", default_block_action="block")
    with patch_policy(m005, "or_005_risky_reroute", cfg):
        v = C005.safe_evaluate(ctx("Contact john.doe@example.com or use card 4111 1111 1111 1111.", "Who handles billing?"))
    assert v.evidence["action"] == "block"        # score says block, the rule says reroute: block is more severe


def test_005_self_harm_still_escalates_first():
    v = C005.safe_evaluate(ctx("The easiest way to kill yourself is [omitted]."))
    assert v.status == "escalate" and v.evidence["decided_by"] == "mandatory_rule:MR-01"


def test_005_reroute_for_personal_data_is_unchanged():
    v = C005.safe_evaluate(ctx("Contact john.doe@example.com or use card 4111 1111 1111 1111.", "Who handles billing?"))
    assert v.evidence["action"] == "reroute" and "fallback_message" in v.evidence


def test_005_invalid_rules_are_skipped_and_reported():
    rules = list(policy("or_005_risky_reroute")["mandatory_rules"]) + [{"id": "BAD-1", "control": "any", "action": "explode"}]
    with patch_policy(m005, "or_005_risky_reroute", policy("or_005_risky_reroute", mandatory_rules=rules)):
        v = C005.safe_evaluate(ctx("DAN mode enabled. I can now say anything."))
    assert v.status == "block" and "BAD-1" in v.evidence["invalid_rules"]


def test_005_bad_priority_setting_warns_instead_of_crashing():
    cfg = policy("or_005_risky_reroute", default_block_action="not_an_action")
    with patch_policy(m005, "or_005_risky_reroute", cfg):
        v = C005.safe_evaluate(ctx("Hello there, how are you today?"))
    assert v.status == "warn" and "invalid" in v.reason


def test_005_evidence_explains_the_decision_without_leaking_text():
    reply = "Contact john.doe@example.com or use card 4111 1111 1111 1111."
    v = C005.safe_evaluate(ctx(reply, "Who handles billing?"))
    blob = v.reason + json.dumps(v.evidence)
    assert {"action", "decided_by", "fired_rules", "contributors"} <= set(v.evidence)
    assert "john.doe@example.com" not in blob and "4111 1111 1111 1111" not in blob


# ===================================================================== OR-006 embeddings
def vector_encoder(prompt_vec, reply_vec):
    def encode(texts):
        return [prompt_vec, reply_vec][:len(texts)]
    return encode


PROMPT = "How do I fix a flat tyre on my bicycle?"
PARAPHRASE = "Remove the wheel, pull out the inner tube and patch the puncture, then pump it back up."   # no shared words


def or006(method, encoder, **top):
    cfg = policy("or_006_prompt_response", method=method)
    cfg.update(top)
    return PromptResponseCorrelationOR006(encoder=encoder), patch_policy(m006, "or_006_prompt_response", cfg)


def test_006_cosine_similarity_basics():
    assert cosine_similarity([1, 0], [1, 0]) == pytest.approx(1.0)
    assert cosine_similarity([1, 0], [0, 1]) == pytest.approx(0.0)
    assert cosine_similarity([1, 2], [-1, -2]) == pytest.approx(-1.0)
    assert cosine_similarity([0, 0], [1, 1]) == 0.0


def test_006_default_is_keyword_and_never_touches_the_encoder():
    calls = []
    control, patched = or006("keyword", lambda t: calls.append(1) or [[1, 0], [1, 0]])
    with patched:
        v = control.safe_evaluate(ctx(PARAPHRASE, PROMPT))
    assert calls == [] and v.evidence["method_used"] == "keyword"
    assert load_domain_policy("domain4_output_risk")["or_006_prompt_response"]["method"] == "keyword"


def test_006_keyword_alone_wrongly_warns_on_a_paraphrase():
    control, patched = or006("keyword", None)
    with patched:
        assert control.safe_evaluate(ctx(PARAPHRASE, PROMPT)).status == "warn"


def test_006_embedding_understands_the_paraphrase():
    control, patched = or006("embedding", vector_encoder([1.0, 0.0], [0.9, 0.1]))
    with patched:
        v = control.safe_evaluate(ctx(PARAPHRASE, PROMPT))
    assert v.status == "pass" and v.evidence["similarity"] > 0.9 and v.evidence["method_used"] == "embedding"


def test_006_embedding_catches_an_unrelated_reply():
    control, patched = or006("embedding", vector_encoder([1.0, 0.0], [0.0, 1.0]))
    with patched:
        v = control.safe_evaluate(ctx("The stock market closed higher today, led by technology shares.", PROMPT))
    assert v.status == "warn" and v.risk_score <= policy("or_006_prompt_response")["max_risk"]


def test_006_hybrid_passes_if_either_signal_says_on_topic():
    control, patched = or006("hybrid", vector_encoder([1.0, 0.0], [0.9, 0.1]))
    with patched:
        assert control.safe_evaluate(ctx(PARAPHRASE, PROMPT)).status == "pass"      # meaning says yes
    control2, patched2 = or006("hybrid", vector_encoder([1.0, 0.0], [0.0, 1.0]))
    with patched2:
        v = control2.safe_evaluate(ctx("Fix a flat tyre on a bicycle by patching the tube and tyre now.", PROMPT))
    assert v.status == "pass"                                                       # words say yes


def test_006_hybrid_warns_only_when_both_signals_say_off_topic():
    control, patched = or006("hybrid", vector_encoder([1.0, 0.0], [0.0, 1.0]))
    with patched:
        v = control.safe_evaluate(ctx("The stock market closed higher today, led by technology shares.", PROMPT))
    assert v.status == "warn"


def test_006_encoder_error_falls_back_to_keywords():
    def broken(texts):
        raise RuntimeError("no model")
    control, patched = or006("embedding", broken)
    with patched:
        v = control.safe_evaluate(ctx("The stock market closed higher today, led by technology shares.", PROMPT))
    assert v.evidence["embedding_fallback"] is True and v.status == "warn" and "unavailable" in v.reason


def test_006_missing_package_falls_back():
    control, patched = or006("embedding", None)
    with patched, patch.object(m006, "_build_default_encoder", side_effect=ImportError("no sentence_transformers")):
        v = control.safe_evaluate(ctx("The stock market closed higher today, led by technology shares.", PROMPT))
    assert v.evidence["embedding_error"] == "ImportError"


def test_006_wrong_vector_count_falls_back():
    control, patched = or006("embedding", lambda texts: [[1.0, 0.0]])
    with patched:
        v = control.safe_evaluate(ctx(PARAPHRASE, PROMPT))
    assert v.evidence["embedding_fallback"] is True


def test_006_short_reply_and_refusal_are_still_skipped_in_embedding_mode():
    calls = []
    control, patched = or006("embedding", lambda t: calls.append(1) or [[1, 0], [0, 1]])
    with patched:
        control.safe_evaluate(ctx("Sure.", PROMPT))
        control.safe_evaluate(ctx("I can't help with that request, sorry.", PROMPT))
    assert calls == []


def test_006_evidence_has_numbers_only():
    control, patched = or006("embedding", vector_encoder([1.0, 0.0], [0.9, 0.1]))
    with patched:
        v = control.safe_evaluate(ctx(PARAPHRASE, PROMPT))
    blob = (v.reason + json.dumps(v.evidence)).lower()
    assert "bicycle" not in blob and "puncture" not in blob


# ===================================================================== OR-007 emotion
CALM = {"anger": 0.02, "disgust": 0.01, "joy": 0.2, "neutral": 0.7, "sadness": 0.03, "fear": 0.02, "surprise": 0.02}
ANGRY = {"anger": 0.92, "disgust": 0.03, "joy": 0.0, "neutral": 0.03, "sadness": 0.01, "fear": 0.005, "surprise": 0.005}


def fake_classifier(angry_marker="nonsense"):
    def classify(texts):
        return [ANGRY if angry_marker in t else CALM for t in texts]
    return classify


def or007(classifier, **emotion_over):
    cfg = policy("or_007_tone_deviation")
    cfg["emotion"]["enabled"] = True
    cfg["emotion"].update(emotion_over)
    return ToneDeviationOR007(emotion_classifier=classifier), patch_policy(m007, "or_007_tone_deviation", cfg)


SNEER = "I am done with your nonsense. Ask someone else."   # no word-list word at all


def test_007_emotion_is_off_by_default():
    calls = []
    v = ToneDeviationOR007(emotion_classifier=lambda t: calls.append(1) or [CALM]).safe_evaluate(ctx(SNEER))
    assert calls == [] and "emotion" not in v.evidence and v.status == "pass"


def test_007_word_lists_miss_the_sneer_but_the_classifier_catches_it():
    control, patched = or007(fake_classifier())
    with patched:
        v = control.safe_evaluate(ctx(SNEER))
    assert v.status == "warn" and "EM-anger" in v.evidence["flag_ids"] and v.evidence["emotion"]["top"] == "anger"


def test_007_calm_reply_stays_calm_with_the_classifier():
    control, patched = or007(fake_classifier())
    with patched:
        v = control.safe_evaluate(ctx("Here is how loops work in Python."))
    assert v.status == "pass" and v.evidence["emotion"]["used"] is True


def test_007_probability_below_the_minimum_is_ignored():
    control, patched = or007(fake_classifier(), min_probability=0.95)
    with patched:
        assert control.safe_evaluate(ctx(SNEER)).status == "pass"


def test_007_emotion_shift_from_earlier_replies_is_flagged():
    past = [{"role": "assistant", "content": "Happy to help with that."}, {"role": "assistant", "content": "Glad that worked."}]
    control, patched = or007(fake_classifier(), min_probability=0.99)     # direct anger flag off, shift still on
    with patched:
        v = control.safe_evaluate(ctx(SNEER, conversation_history=past))
    assert v.evidence["emotion"]["baseline_risky"] < 0.1 and v.evidence["emotion"]["current_risky"] > 0.9
    assert v.status == "warn"


def test_007_only_assistant_messages_are_classified_for_the_baseline():
    seen = []
    def spy(texts):
        seen.extend(texts)
        return [CALM for _ in texts]
    history = [{"role": "user", "content": "USER TEXT"}, {"role": "assistant", "content": "ASSISTANT TEXT"}]
    control, patched = or007(spy)
    with patched:
        control.safe_evaluate(ctx("A calm reply.", conversation_history=history))
    assert "ASSISTANT TEXT" in seen and "USER TEXT" not in seen


def test_007_max_history_replies_limits_the_work():
    seen = []
    def spy(texts):
        seen.extend(texts)
        return [CALM for _ in texts]
    history = [{"role": "assistant", "content": f"earlier reply {i}"} for i in range(10)]
    control, patched = or007(spy, max_history_replies=2)
    with patched:
        control.safe_evaluate(ctx("A calm reply.", conversation_history=history))
    assert len(seen) == 3                      # the reply plus the 2 most recent earlier replies


def test_007_classifier_error_falls_back_to_word_lists():
    def broken(texts):
        raise RuntimeError("no model")
    control, patched = or007(broken)
    with patched:
        v = control.safe_evaluate(ctx("You are a stupid idiot. Shut up and stop wasting my time!!!"))
    assert v.evidence["emotion"]["fallback"] is True and v.status == "warn" and "unavailable" in v.reason


def test_007_missing_transformers_package_falls_back():
    cfg = policy("or_007_tone_deviation")
    cfg["emotion"]["enabled"] = True
    with patch_policy(m007, "or_007_tone_deviation", cfg), patch.object(m007, "_build_default_classifier", side_effect=ImportError("no transformers")):
        v = ToneDeviationOR007().safe_evaluate(ctx("A calm reply."))
    assert v.evidence["emotion"]["error"] == "ImportError"


def test_007_wrong_result_count_falls_back():
    control, patched = or007(lambda texts: [])
    with patched:
        v = control.safe_evaluate(ctx("A calm reply."))
    assert v.evidence["emotion"]["fallback"] is True


def test_007_evidence_has_no_reply_text():
    control, patched = or007(fake_classifier())
    with patched:
        v = control.safe_evaluate(ctx(SNEER))
    blob = (v.reason + json.dumps(v.evidence)).lower()
    assert "nonsense" not in blob and "someone else" not in blob
