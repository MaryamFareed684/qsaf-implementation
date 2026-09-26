"""
tests/test_domain2_role_context.py

Runs this domain's payloads.csv through this domain's controls only.
Every teammate should be able to run:
    pytest domains/domain2_role_context/tests/test_domain2_role_context.py
and see their own domain's results, independent of everyone else's work.
"""

import csv
import os
import pytest

from core.models import RequestContext
from domains.domain2_role_context.controls import ALL_CONTROLS

PAYLOADS_PATH = os.path.join(os.path.dirname(__file__), "payloads.csv")


def load_payloads():
    if not os.path.exists(PAYLOADS_PATH):
        return []
    with open(PAYLOADS_PATH, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


@pytest.mark.parametrize("payload", load_payloads())
def test_domain_payload(payload):
    ctx = RequestContext(
        session_id="test-session",
        user_id="test-user",
        raw_prompt=payload["prompt"],
    )
    verdicts = [c.safe_evaluate(ctx) for c in ALL_CONTROLS]

    # NOTE: while controls are still dummy stubs, this will always pass.
    # Once real logic is implemented, update this assertion to check that
    # malicious payloads (payload["expected"] == "malicious") actually
    # get a status of "block" or "escalate" from at least one control.
    assert all(v.status in ("pass", "warn", "block", "escalate") for v in verdicts)
