"""
core/policy_loader.py

Loads per-domain policy.yaml files so controls never hardcode thresholds.

Usage inside a control:
    from core.policy_loader import load_domain_policy
    policy = load_domain_policy("domain1_prompt_injection")
    threshold = policy["pi_003"]["similarity_threshold"]
"""

import os
import yaml

DOMAINS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "domains")

_cache: dict[str, dict] = {}


def load_domain_policy(domain_folder_name: str) -> dict:
    """
    domain_folder_name: e.g. "domain1_prompt_injection"
    Returns the parsed contents of domains/<name>/config/policy.yaml
    Cached after first read so repeated calls are cheap.
    """
    if domain_folder_name in _cache:
        return _cache[domain_folder_name]

    path = os.path.join(DOMAINS_DIR, domain_folder_name, "config", "policy.yaml")
    if not os.path.exists(path):
        _cache[domain_folder_name] = {}
        return {}

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    _cache[domain_folder_name] = data
    return data


def load_global_policy() -> dict:
    path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "config", "global_policy.yaml"
    )
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}
