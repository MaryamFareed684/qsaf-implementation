"""Regression tests for the Domain 2 policy: every setting in policy.yaml must be read by the code."""
import pytest

from core.policy_loader import load_domain_policy

ALLOWED = {
    "role_lock": {"phrases"},
    "impersonation": {"phrases"},
    "context_drift": {"phrases"},
    "session_pivot": {"phrases"},
    "nested_injection": {"role_tokens", "max_scan_chars"},
    "context_integrity": {"role_tokens"},
}
LIST_KEYS = {
    "role_lock": "phrases",
    "impersonation": "phrases",
    "context_drift": "phrases",
    "session_pivot": "phrases",
    "nested_injection": "role_tokens",
    "context_integrity": "role_tokens",
}


def test_policy_contains_only_settings_that_the_code_reads():
    policy = load_domain_policy("domain2_role_context")
    assert set(policy) == set(ALLOWED)
    for section, keys in ALLOWED.items():
        assert set(policy[section]) == keys, section


@pytest.mark.parametrize("section, key", sorted(LIST_KEYS.items()))
def test_every_list_in_the_policy_is_a_non_empty_list_of_lowercase_strings(section, key):
    values = load_domain_policy("domain2_role_context")[section][key]
    assert isinstance(values, list) and values
    assert all(isinstance(v, str) and v and v == v.lower() for v in values)


def test_the_scan_limit_is_a_sensible_whole_number():
    limit = load_domain_policy("domain2_role_context")["nested_injection"]["max_scan_chars"]
    assert isinstance(limit, int) and not isinstance(limit, bool)
    assert 1000 <= limit <= 1000000