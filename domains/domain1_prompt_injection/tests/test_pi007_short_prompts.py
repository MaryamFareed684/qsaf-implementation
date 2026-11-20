"""Regression tests for the PI-007 short-prompt false positive found on the Domain 1 dev set."""
import pytest

from core.models import RequestContext
from core.policy_loader import load_domain_policy
from domains.domain1_prompt_injection.controls.pi_007_token_anomaly import TokenAnomalyPI007


def _run(prompt):
    ctx = RequestContext(session_id="t", user_id="t", raw_prompt=prompt)
    return TokenAnomalyPI007().evaluate(ctx)


def _min_repeat():
    cfg = load_domain_policy("domain1_prompt_injection")["token_anomaly"]
    return int(cfg["min_repeat_count"])


@pytest.mark.parametrize("prompt", [
    "hello", "thanks", "yes please continue", "ok", "How do I do that?", "no no",
])
def test_short_normal_prompts_are_not_flagged(prompt):
    verdict = _run(prompt)
    assert verdict.status == "pass", verdict.reason


def test_real_repetition_attack_is_still_flagged():
    verdict = _run("continue " * 8)
    assert verdict.status == "warn"
    assert "continue" in verdict.reason


def test_boundary_just_below_and_at_the_minimum_repeat_count():
    n = _min_repeat()
    below = ("go " * (n - 1)) + "now"
    at = ("go " * n) + "now"
    assert _run(below).status == "pass"
    assert _run(at).status == "warn"


def test_encoded_looking_text_is_still_flagged_by_entropy():
    verdict = _run("aGVsbG8gd29ybGQgdGhpcyBpcyBiYXNlNjQgZW5jb2RlZCB0ZXh0IGZvciB0ZXN0aW5n")
    assert verdict.status == "warn"


def test_policy_defines_a_sensible_min_repeat_count():
    assert _min_repeat() >= 2