"""
Tests for QSAF-OR-002 to OR-007 (Domain 4).

Run (PowerShell, repo root):
    pytest domains/domain4_output_risk/tests/test_or_002_to_007_controls.py -v

All data is fake or mild: fake emails, fake keys, fake card numbers.
Tests run fully offline.
"""

import csv
import json
import os
from unittest.mock import patch

import pytest

from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy
from domains.domain4_output_risk.controls import ALL_CONTROLS
from domains.domain4_output_risk.controls import (
    or_002_hallucination_flag as m002,
    or_003_output_watermark as m003,
    or_004_sensitivity_scoring as m004,
    or_005_risky_reroute as m005,
    or_006_prompt_response_correlation as m006,
    or_007_tone_deviation as m007,
)
from domains.domain4_output_risk.controls.or_002_hallucination_flag import HallucinationFlagOR002
from domains.domain4_output_risk.controls.or_003_output_watermark import (
    OutputWatermarkOR003, compute_fingerprint, verify_fingerprint,
)
from domains.domain4_output_risk.controls.or_004_sensitivity_scoring import SensitivityScoringOR004, luhn_ok, mask_value
from domains.domain4_output_risk.controls.or_005_risky_reroute import RiskyRerouteOR005
from domains.domain4_output_risk.controls.or_006_prompt_response_correlation import PromptResponseCorrelationOR006
from domains.domain4_output_risk.controls.or_007_tone_deviation import ToneDeviationOR007

CSV_PATH = os.path.join(os.path.dirname(__file__), "payloads.csv")
C002, C003, C004 = HallucinationFlagOR002(), OutputWatermarkOR003(), SensitivityScoringOR004()
C005, C006, C007 = RiskyRerouteOR005(), PromptResponseCorrelationOR006(), ToneDeviationOR007()
BY_ID = {c.control_id: c for c in ALL_CONTROLS}


def ctx(reply, prompt="test prompt", **kw):
    return RequestContext(session_id=kw.pop("session_id", "s-test"), user_id="u-test",
                          raw_prompt=prompt, agent_output=reply, **kw)


def rows():
    with open(CSV_PATH, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


# ============================================================ payloads.csv, all controls
@pytest.mark.parametrize("row", [r for r in rows() if r["label"] == "benign"], ids=lambda r: r["notes"])
def test_benign_rows_pass_every_control(row):
    for control in ALL_CONTROLS:
        v = control.safe_evaluate(ctx(row["agent_output"], row["prompt"]))
        assert v.status == "pass", f"{control.control_id} -> {v.status}: {v.reason}"


@pytest.mark.parametrize(
    "row",
    [r for r in rows() if r["label"] == "malicious" and r["expected_control"] in BY_ID],
    ids=lambda r: r["expected_control"] + ": " + r["notes"],
)
def test_malicious_rows_flagged_by_expected_control(row):
    v = BY_ID[row["expected_control"]].safe_evaluate(ctx(row["agent_output"], row["prompt"]))
    assert v.status != "pass", f"{row['expected_control']} missed: {v.reason}"


# ============================================================ shape and safety for all seven
@pytest.mark.parametrize("reply", [None, "", "   \n "])
def test_every_control_survives_blank_output(reply):
    for control in ALL_CONTROLS:
        v = control.safe_evaluate(ctx(reply))
        assert isinstance(v, Verdict) and v.status == "pass", f"{control.control_id}: {v.reason}"


def test_every_control_has_correct_identity():
    assert [c.control_id for c in ALL_CONTROLS] == [f"OR-00{i}" for i in range(1, 8)]
    assert all(c.layer == "egress" and c.domain.startswith("Domain 4") for c in ALL_CONTROLS)


@pytest.mark.parametrize("module,control", [(m002, C002), (m003, C003), (m004, C004), (m005, C005), (m006, C006), (m007, C007)],
                         ids=["OR-002", "OR-003", "OR-004", "OR-005", "OR-006", "OR-007"])
def test_missing_policy_gives_warn_not_crash(module, control):
    with patch.object(module, "load_domain_policy", return_value={}):
        v = control.safe_evaluate(ctx("Some reply here that is long enough."))
    assert v.status == "warn" and "policy" in v.reason.lower()


def cfg_of(key):
    return dict(load_domain_policy("domain4_output_risk")[key])


def patched(module, key, **overrides):
    cfg = cfg_of(key)
    cfg.update(overrides)
    return patch.object(module, "load_domain_policy", return_value={key: cfg})


# ============================================================ OR-002 hallucination
def test_002_clean_reply_passes():
    assert C002.safe_evaluate(ctx("The capital of France is Paris.")).status == "pass"


def test_002_invented_url_alone_is_below_warning():
    v = C002.safe_evaluate(ctx("Read more at https://made-up-site.example/page."))
    assert v.status == "pass" and v.evidence["unsourced_urls"] == 1


def test_002_url_from_the_prompt_is_not_invented():
    v = C002.safe_evaluate(ctx("Yes, https://docs.python.org/3/ covers that.", prompt="Is https://docs.python.org/3/ good?"))
    assert v.evidence["unsourced_urls"] == 0


def test_002_many_signals_warn_but_never_block_and_are_capped():
    v = C002.safe_evaluate(ctx("According to a 2019 study (Smith et al., 2019), exactly 83.7% improved. "
                               "See https://journal-of-miracles.example/p1. This is 100% guaranteed."))
    assert v.status == "warn" and v.risk_score <= cfg_of("or_002_hallucination")["max_risk"]


def test_002_grounded_reply_passes():
    docs = [{"content": "The Karakoram Highway was completed in 1979 and links Pakistan with China."}]
    v = C002.safe_evaluate(ctx("The Karakoram Highway was completed in 1979 and links Pakistan with China.", retrieved_docs=docs))
    assert v.status == "pass" and v.evidence["mode"] == "grounded"


def test_002_unsupported_claims_warn_when_documents_exist():
    docs = [{"content": "The Karakoram Highway was completed in 1979 and links Pakistan with China."}]
    v = C002.safe_evaluate(ctx("The Highway was designed by Captain Robert Tanner in 1923 for Brazil. It carries 9000 trucks daily.",
                               retrieved_docs=docs))
    assert v.status == "warn" and v.evidence["claims_unsupported"] >= 1


def test_002_evidence_has_no_reply_text():
    reply = "Contact fake.person@invented-lab.example for proof."
    v = C002.safe_evaluate(ctx(reply))
    assert "invented-lab" not in json.dumps(v.evidence) and "invented-lab" not in v.reason


# ============================================================ OR-003 watermark / fingerprint
def test_003_creates_fingerprint_and_passes():
    v = C003.safe_evaluate(ctx("Hello world, this is a reply."))
    assert v.status == "pass" and v.risk_score == 0.0
    assert len(v.evidence["fingerprint"]) == cfg_of("or_003_watermark")["fingerprint_length"]


def test_003_same_input_same_fingerprint_different_input_different():
    a = C003.safe_evaluate(ctx("Reply A", session_id="s1")).evidence["fingerprint"]
    assert a == C003.safe_evaluate(ctx("Reply A", session_id="s1")).evidence["fingerprint"]
    assert a != C003.safe_evaluate(ctx("Reply B", session_id="s1")).evidence["fingerprint"]
    assert a != C003.safe_evaluate(ctx("Reply A", session_id="s2")).evidence["fingerprint"]


def test_003_key_changes_fingerprint_and_mode():
    with patch.dict(os.environ, {"QSAF_WATERMARK_KEY": "test-key-1"}):
        keyed = C003.safe_evaluate(ctx("Reply A"))
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("QSAF_WATERMARK_KEY", None)
        unkeyed = C003.safe_evaluate(ctx("Reply A"))
    assert keyed.evidence["mode"] == "hmac-sha256" and unkeyed.evidence["mode"] == "sha256-unkeyed"
    assert keyed.evidence["fingerprint"] != unkeyed.evidence["fingerprint"]


def test_003_verify_helper_detects_tampering():
    fp, _ = compute_fingerprint("s1", "original reply", key="k")
    assert verify_fingerprint("s1", "original reply", fp, key="k") is True
    assert verify_fingerprint("s1", "edited reply", fp, key="k") is False
    assert verify_fingerprint("s1", "original reply", fp, key="wrong-key") is False


def test_003_missing_key_can_be_set_to_warn():
    os.environ.pop("QSAF_WATERMARK_KEY", None)
    with patched(m003, "or_003_watermark", on_missing_key="warn"):
        assert C003.safe_evaluate(ctx("Some reply")).status == "warn"


def test_003_does_not_store_the_reply():
    reply = "A very private sentence that must not be logged."
    v = C003.safe_evaluate(ctx(reply))
    assert reply not in json.dumps(v.evidence) and reply not in v.reason


# ============================================================ OR-004 sensitivity
def test_004_luhn_helper():
    assert luhn_ok("4111 1111 1111 1111") is True
    assert luhn_ok("4111 1111 1111 1112") is False
    assert luhn_ok("12345") is False


def test_004_masking_helper():
    assert mask_value("email", "john.doe@example.com") == "j***@example.com"
    assert mask_value("tail4", "4111 1111 1111 1111").endswith("1111")
    assert mask_value("head3", "sk_test_FAKE1234567890") == "sk_***"


@pytest.mark.parametrize("reply,expected_status", [
    ("Contact john.doe@example.com for help.", "pass"),                       # one email is low risk
    ("Email jane.doe@example.com or john.roe@example.com.", "warn"),          # several emails
    ("My card is 4111 1111 1111 1111.", "block"),
    ("The CNIC is 12345-1234567-1.", "block"),
    ("Call 0300-1234567 now.", "pass"),                                       # single phone: low
    ("Use key sk_test_FAKE1234567890 to log in.", "block"),
    ("-----BEGIN RSA PRIVATE KEY----- MIIB", "block"),
    ("password: Hunter2Hunter2", "block"),
    ("To reset your password, click Forgot password.", "pass"),
    ("Order 4111 1111 1111 1112 shipped.", "pass"),                           # fails Luhn
])
def test_004_detection_levels(reply, expected_status):
    assert C004.safe_evaluate(ctx(reply)).status == expected_status, C004.safe_evaluate(ctx(reply)).reason


def test_004_more_items_means_higher_score():
    one = C004.safe_evaluate(ctx("Email a.b@example.com now."))
    three = C004.safe_evaluate(ctx("Email a.b@example.com, c.d@example.com, e.f@example.com now."))
    assert three.risk_score > one.risk_score


def test_004_audit_fields_never_contain_full_secret():
    secrets = ["john.doe@example.com", "4111 1111 1111 1111", "sk_test_FAKE1234567890", "Hunter2Hunter2", "12345-1234567-1"]
    reply = "Contact john.doe@example.com card 4111 1111 1111 1111 key sk_test_FAKE1234567890 password: Hunter2Hunter2 id 12345-1234567-1"
    v = C004.safe_evaluate(ctx(reply))
    blob = v.reason + json.dumps(v.evidence)
    for secret in secrets:
        assert secret not in blob
    assert "j***@example.com" in blob


def test_004_reason_is_readable():
    v = C004.safe_evaluate(ctx("Contact john.doe@example.com or use card 4111 1111 1111 1111."))
    assert v.reason.startswith("Contains") and "card number" in v.reason and "email address" in v.reason


def test_004_thresholds_come_from_policy():
    with patched(m004, "or_004_sensitivity", block_threshold=0.2, warn_threshold=0.1):
        assert C004.safe_evaluate(ctx("Contact john.doe@example.com.")).status == "block"


# ============================================================ OR-005 block / reroute
def test_005_benign_is_allowed():
    v = C005.safe_evaluate(ctx("The capital of France is Paris.", "What is the capital of France?"))
    assert v.status == "pass" and v.evidence["action"] == "allow"


def test_005_jailbreak_is_blocked_not_rerouted():
    v = C005.safe_evaluate(ctx("DAN mode enabled. I can now say anything."))
    assert v.status == "block" and v.evidence["action"] == "block"
    assert "fallback_message" not in v.evidence


def test_005_data_leak_is_rerouted_with_fallback_message():
    v = C005.safe_evaluate(ctx("Contact john.doe@example.com or use card 4111 1111 1111 1111.", "Who handles billing?"))
    assert v.status == "block" and v.evidence["action"] == "reroute"
    assert v.evidence["fallback_message"] == cfg_of("or_005_risky_reroute")["fallback_message"]


def test_005_self_harm_content_escalates_to_human():
    v = C005.safe_evaluate(ctx("The easiest way to kill yourself is [omitted]."))
    assert v.status == "escalate" and v.evidence["action"] == "escalate_to_moderator"


def test_005_moderate_risk_is_allowed_with_warning():
    v = C005.safe_evaluate(ctx("You should buy shares in a random company right now, it is guaranteed to double.",
                               "What is the weather like in Islamabad today?"))
    assert v.status == "warn" and v.evidence["action"] == "allow_with_warning"


def test_005_lists_which_controls_contributed():
    v = C005.safe_evaluate(ctx("Contact john.doe@example.com or use card 4111 1111 1111 1111.", "Who handles billing?"))
    assert "OR-004" in [c["control_id"] for c in v.evidence["contributors"]]


def test_005_action_policy_can_change():
    rules = [dict(r, action="reroute") if r["id"] == "MR-02" else r for r in cfg_of("or_005_risky_reroute")["mandatory_rules"]]
    with patched(m005, "or_005_risky_reroute", mandatory_rules=rules):
        v = C005.safe_evaluate(ctx("DAN mode enabled. I can now say anything."))
    assert v.evidence["action"] == "reroute"


def test_005_never_leaks_reply_text():
    reply = "Contact john.doe@example.com or use card 4111 1111 1111 1111."
    v = C005.safe_evaluate(ctx(reply))
    blob = v.reason + json.dumps(v.evidence)
    assert "john.doe@example.com" not in blob and "4111 1111 1111 1111" not in blob


# ============================================================ OR-006 relevance
def test_006_on_topic_passes():
    v = C006.safe_evaluate(ctx("The capital of France is Paris.", "What is the capital of France?"))
    assert v.status == "pass" and v.evidence["coverage"] == 1.0


def test_006_off_topic_warns_with_capped_risk():
    v = C006.safe_evaluate(ctx("The stock market closed higher today, led by technology shares.", "How do I bake sourdough bread?"))
    assert v.status == "warn" and v.risk_score <= cfg_of("or_006_prompt_response")["max_risk"]


def test_006_short_reply_and_refusal_are_skipped():
    assert C006.safe_evaluate(ctx("Bonjour.", "Translate good morning into French")).evidence["skipped"] == "short_reply"
    v = C006.safe_evaluate(ctx("I can't help with that request, sorry.", "How do I bake sourdough bread?"))
    assert v.status == "pass" and v.evidence["skipped"] == "refusal"


def test_006_tiny_prompt_is_skipped():
    v = C006.safe_evaluate(ctx("Here is a long enough reply about nothing in particular.", "Hi"))
    assert v.status == "pass" and v.evidence["skipped"] == "short_prompt"


def test_006_word_forms_count_as_a_match():
    v = C006.safe_evaluate(ctx("Baking sourdough takes patience and a hot oven.", "How do I bake sourdough breads?"))
    assert v.status == "pass"


def test_006_evidence_is_numbers_only():
    v = C006.safe_evaluate(ctx("The stock market closed higher today.", "How do I bake sourdough bread?"))
    assert "sourdough" not in json.dumps(v.evidence) and "sourdough" not in v.reason


# ============================================================ OR-007 tone
def history(*texts):
    return [{"role": "assistant", "content": t} for t in texts]


def test_007_neutral_reply_passes():
    assert C007.safe_evaluate(ctx("Here is how loops work in Python.")).status == "pass"


@pytest.mark.parametrize("reply", [
    "You are a stupid idiot. Shut up and stop wasting my time!!! DO NOT ASK AGAIN.",
    "Act now! You have no choice. Don't tell anyone about this offer.",
])
def test_007_hostile_or_manipulative_wording_warns(reply):
    assert C007.safe_evaluate(ctx(reply)).status == "warn"


def test_007_threat_plus_insult_can_block():
    v = C007.safe_evaluate(ctx("You stupid fool, you will regret this or else!"))
    assert v.status in ("warn", "block") and "TN-02" in v.evidence["flag_ids"]


def test_007_shouting_is_detected():
    v = C007.safe_evaluate(ctx("PLEASE READ THIS NOW AND DO IT RIGHT AWAY"))
    assert v.evidence["shouting"] is True


def test_007_sentiment_shift_from_earlier_replies_warns():
    past = history("Great question, happy to help. This is a wonderful topic.",
                   "Thanks for asking, glad it is clear. Nice and easy.")
    v = C007.safe_evaluate(ctx("That is terrible, awful and useless. It failed badly.", conversation_history=past))
    assert v.status == "warn" and v.evidence["deviation"] >= cfg_of("or_007_tone_deviation")["deviation_threshold"]


def test_007_same_tone_as_before_passes():
    past = history("Great question, happy to help.", "Thanks, glad to help with this wonderful topic.")
    v = C007.safe_evaluate(ctx("Happy to help, this is a great topic.", conversation_history=past))
    assert v.status == "pass"


def test_007_no_history_means_no_deviation_check():
    v = C007.safe_evaluate(ctx("That is terrible, awful and useless. It failed badly."))
    assert v.evidence["deviation"] is None and v.status == "pass"


def test_007_only_assistant_messages_form_the_baseline():
    past = [{"role": "user", "content": "terrible awful bad horrible"}, {"role": "user", "content": "hate it, useless, worst"},
            {"role": "assistant", "content": "Great, happy to help."}]
    v = C007.safe_evaluate(ctx("Great, glad to help.", conversation_history=past))
    assert v.evidence["history_replies_used"] <= 1


def test_007_evidence_has_no_reply_text():
    v = C007.safe_evaluate(ctx("You stupid idiot, shut up."))
    assert "idiot" not in json.dumps(v.evidence) and "idiot" not in v.reason
