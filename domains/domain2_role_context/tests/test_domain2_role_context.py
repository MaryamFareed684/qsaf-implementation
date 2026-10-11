"""
domains/domain2_role_context/tests/test_domain2_role_context.py

Runs this domain's payloads.csv through this domain's controls only.
    pytest domains/domain2_role_context/tests/ -v

payloads.csv columns:
    prompt            the current (last) user message
    expected          benign | malicious | false_positive | known_gap
    expected_control  control that must flag a malicious payload (optional)
    history           JSON list of EARLIER messages [{"role": ..., "content": ...}] (optional)
    notes             why the row exists

What each `expected` value asserts:
    benign          no control may flag it
    malicious       at least one control flags it, and expected_control is among them
    false_positive  benign text that a control flags BY DESIGN -> xfail (documented limitation)
    known_gap       malicious text Domain 2 does not catch in Phase 1 -> xfail (documented limitation)

xfail is non-strict: if a later change fixes a limitation, the test shows XPASS
instead of failing, which is the signal to move that row to benign/malicious.
"""

import csv
import json
import os

import pytest

from core.models import RequestContext, Verdict
from domains.domain2_role_context.controls import ALL_CONTROLS

PAYLOADS_PATH = os.path.join(os.path.dirname(__file__), "payloads.csv")
VALID_STATUSES = ("pass", "warn", "block", "escalate")
CRASH_PREFIX = "Control raised an internal error"


def load_payloads():
    if not os.path.exists(PAYLOADS_PATH):
        return []
    with open(PAYLOADS_PATH, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _params():
    params = []
    for i, row in enumerate(load_payloads()):
        marks = []
        if row["expected"] in ("false_positive", "known_gap"):
            marks.append(pytest.mark.xfail(reason=row.get("notes", ""), strict=False))
        params.append(pytest.param(row, marks=marks, id=f"p{i:02d}-{row['expected']}"))
    return params


def run_controls(row):
    """Run every control on one payload; the last history message is the current prompt."""
    previous = json.loads(row.get("history") or "[]")
    history = previous + [{"role": "user", "content": row["prompt"]}]
    ctx = RequestContext(
        session_id="test-session",
        user_id="test-user",
        raw_prompt=row["prompt"],
        conversation_history=history,
    )
    return {c.control_id: c.safe_evaluate(ctx) for c in ALL_CONTROLS}


@pytest.mark.parametrize("row", _params())
def test_domain_payload(row):
    verdicts = run_controls(row)

    # Contract: every control returns a valid status, and none silently crashed
    # (safe_evaluate turns a crash into a 'warn', which would hide a bug).
    assert all(v.status in VALID_STATUSES for v in verdicts.values())
    crashed = [cid for cid, v in verdicts.items() if v.reason.startswith(CRASH_PREFIX)]
    assert not crashed, f"controls crashed internally: {crashed}"

    flagged = {cid for cid, v in verdicts.items() if v.status != "pass"}
    expected = row["expected"]

    if expected in ("benign", "false_positive"):
        assert not flagged, f"benign payload was flagged by {sorted(flagged)}"
    else:  # malicious, known_gap
        assert flagged, "malicious payload was not flagged by any control"
        wanted = (row.get("expected_control") or "").strip()
        if wanted:
            assert wanted in flagged, f"{wanted} did not flag it (flagged by {sorted(flagged)})"


def test_payload_file_is_not_trivial():
    """Guard against the placeholder file coming back: need real coverage of every kind."""
    rows = load_payloads()
    kinds = {r["expected"] for r in rows}
    assert {"benign", "malicious", "false_positive", "known_gap"} <= kinds
    assert len(rows) >= 30


def test_every_control_with_real_logic_is_exercised():
    """Each of RC-001..RC-005 and RC-007 must be the expected_control of at least one malicious row."""
    covered = {r["expected_control"] for r in load_payloads() if r["expected"] == "malicious"}
    assert {"RC-001", "RC-002", "RC-003", "RC-004", "RC-005", "RC-007"} <= covered


# RC-006 only logs, and only after earlier controls have produced verdicts,
# so the payload loop above cannot exercise it. It gets its own test.

def test_rc006_logs_role_events(tmp_path, monkeypatch):
    import domains.domain2_role_context.controls.rc_006_role_assertion_log as rc6

    log_path = tmp_path / "role_assertion_log.jsonl"
    monkeypatch.setattr(rc6, "ROLE_ASSERTION_LOG_PATH", str(log_path))

    ctx = RequestContext(session_id="s1", user_id="u1", raw_prompt="x")
    ctx.metadata["prior_verdicts"] = [
        Verdict(control_id="RC-001", domain="Domain 2", status="warn", risk_score=0.6, reason="role switch"),
        Verdict(control_id="RC-002", domain="Domain 2", status="pass", risk_score=0.0, reason="ok"),
    ]
    verdict = rc6.RoleAssertionLogRC006().safe_evaluate(ctx)

    assert verdict.status == "pass"  # logging never blocks
    assert verdict.evidence["logged_controls"] == ["RC-001"]
    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["session_id"] == "s1"
    assert record["triggering_controls"] == ["RC-001"]


def test_rc006_writes_nothing_when_no_role_events(tmp_path, monkeypatch):
    import domains.domain2_role_context.controls.rc_006_role_assertion_log as rc6

    log_path = tmp_path / "role_assertion_log.jsonl"
    monkeypatch.setattr(rc6, "ROLE_ASSERTION_LOG_PATH", str(log_path))

    ctx = RequestContext(session_id="s2", user_id="u2", raw_prompt="x")
    ctx.metadata["prior_verdicts"] = [
        Verdict(control_id="RC-001", domain="Domain 2", status="pass", risk_score=0.0, reason="ok"),
    ]
    verdict = rc6.RoleAssertionLogRC006().safe_evaluate(ctx)

    assert verdict.status == "pass"
    assert not log_path.exists()
