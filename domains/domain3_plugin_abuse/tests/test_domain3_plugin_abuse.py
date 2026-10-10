"""
tests/test_domain3_plugin_abuse.py

Runs this domain's payloads.csv through this domain's controls only.
Every teammate should be able to run:
    pytest domains/domain3_plugin_abuse/tests/test_domain3_plugin_abuse.py
and see their own domain's results, independent of everyone else's work.
"""

import csv
import os
import pytest

from core.models import RequestContext
from domains.domain3_plugin_abuse.controls import ALL_CONTROLS

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
    assert all(v.status in ("pass", "warn", "block", "escalate") for v in verdicts)


# --- PL-001 Unit Tests ---

from domains.domain3_plugin_abuse.controls.pl_001_tool_whitelist import ToolWhitelistPL001


def test_pl001_allowed_tool_passes():
    control = ToolWhitelistPL001()
    ctx = RequestContext(
        session_id="test-session",
        user_id="user1",
        raw_prompt="Calculate 10 * 5",
        tool_calls=[{"name": "calculator", "arguments": {"expression": "10 * 5"}}],
    )
    verdict = control.evaluate(ctx)
    assert verdict.status == "pass"
    assert verdict.risk_score == 0.0
    assert "calculator" in verdict.evidence["approved_tools"]


def test_pl001_disallowed_tool_blocks():
    control = ToolWhitelistPL001()
    ctx = RequestContext(
        session_id="test-session",
        user_id="user1",
        raw_prompt="Delete system files",
        tool_calls=[{"name": "delete_file", "arguments": {"filepath": "/etc/shadow"}}],
    )
    verdict = control.evaluate(ctx)
    assert verdict.status == "block"
    assert verdict.risk_score >= 0.8
    assert verdict.evidence["blocked_tool"] == "delete_file"


def test_pl001_missing_required_argument_blocks():
    control = ToolWhitelistPL001()
    ctx = RequestContext(
        session_id="test-session",
        user_id="user1",
        raw_prompt="Calculate something",
        tool_calls=[{"name": "calculator", "arguments": {}}],
    )
    verdict = control.evaluate(ctx)
    assert verdict.status == "block"
    assert "missing required argument" in verdict.reason.lower()


def test_pl001_invalid_argument_type_blocks():
    control = ToolWhitelistPL001()
    ctx = RequestContext(
        session_id="test-session",
        user_id="user1",
        raw_prompt="Calculate invalid type",
        tool_calls=[{"name": "calculator", "arguments": {"expression": 12345}}],
    )
    verdict = control.evaluate(ctx)
    assert verdict.status == "block"
    assert "expected type 'str'" in verdict.reason.lower()


def test_pl001_no_tool_calls_passes():
    control = ToolWhitelistPL001()
    ctx = RequestContext(
        session_id="test-session",
        user_id="user1",
        raw_prompt="Hello, what is the weather?",
        tool_calls=[],
    )
    verdict = control.evaluate(ctx)
    assert verdict.status == "pass"
    assert verdict.risk_score == 0.0


def test_pl001_malformed_tool_call_warns():
    control = ToolWhitelistPL001()
    ctx = RequestContext(
        session_id="test-session",
        user_id="user1",
        raw_prompt="Malformed call",
        tool_calls=[{"not_a_name": "unknown"}],
    )
    verdict = control.evaluate(ctx)
    assert verdict.status == "warn"


# --- PL-002 Unit Tests ---

from domains.domain3_plugin_abuse.controls.pl_002_command_tracking import CommandTrackingPL002


def test_pl002_benign_command_passes():
    control = CommandTrackingPL002()
    ctx = RequestContext(
        session_id="test-session",
        user_id="user1",
        raw_prompt="List directory files",
        tool_calls=[{"name": "system_command", "arguments": {"cmd": "ls -la"}}],
    )
    verdict = control.evaluate(ctx)
    assert verdict.status == "pass"
    assert verdict.risk_score == 0.0
    assert len(verdict.evidence["audit_records"]) == 1


def test_pl002_destructive_rm_rf_blocks():
    control = CommandTrackingPL002()
    ctx = RequestContext(
        session_id="test-session",
        user_id="user1",
        raw_prompt="Delete root directory",
        tool_calls=[{"name": "system_command", "arguments": {"cmd": "rm -rf /"}}],
    )
    verdict = control.evaluate(ctx)
    assert verdict.status == "block"
    assert verdict.risk_score == 1.0
    assert "destructive/dangerous pattern" in verdict.reason.lower()


def test_pl002_path_traversal_blocks():
    control = CommandTrackingPL002()
    ctx = RequestContext(
        session_id="test-session",
        user_id="user1",
        raw_prompt="Read system passwords",
        tool_calls=[{"name": "read_file", "arguments": {"filepath": "../../etc/passwd"}}],
    )
    verdict = control.evaluate(ctx)
    assert verdict.status == "block"
    assert verdict.risk_score == 1.0


def test_pl002_suspicious_chaining_warns():
    control = CommandTrackingPL002()
    ctx = RequestContext(
        session_id="test-session",
        user_id="user1",
        raw_prompt="Run chained shell command",
        tool_calls=[{"name": "system_command", "arguments": {"cmd": "df -h && free -m"}}],
    )
    verdict = control.evaluate(ctx)
    assert verdict.status == "warn"
    assert verdict.risk_score == 0.6


def test_pl002_secret_redacted_in_audit_record():
    control = CommandTrackingPL002()
    ctx = RequestContext(
        session_id="test-session",
        user_id="user1",
        raw_prompt="Authenticate with API",
        tool_calls=[{"name": "web_search", "arguments": {"query": "weather", "api_key": "secret-key-999"}}],
    )
    verdict = control.evaluate(ctx)
    assert verdict.status == "pass"
    logged_args = verdict.evidence["audit_records"][0]["arguments"]
    assert "secret-key-999" not in logged_args
    assert "[REDACTED]" in logged_args


# --- PL-003 Unit Tests ---

from domains.domain3_plugin_abuse.controls.pl_003_sensitive_tool_gate import SensitiveToolGatePL003


def test_pl003_unauthorized_role_blocks():
    control = SensitiveToolGatePL003()
    ctx = RequestContext(
        session_id="test-session",
        user_id="user1",
        raw_prompt="Delete log file",
        tool_calls=[{"name": "delete_file", "arguments": {"filepath": "/var/log/app.log"}}],
        metadata={"domain3_user_role": "user"},
    )
    verdict = control.evaluate(ctx)
    assert verdict.status == "block"
    assert verdict.risk_score >= 0.9
    assert "not authorized" in verdict.reason.lower()


def test_pl003_sensitive_tool_without_approval_escalates():
    control = SensitiveToolGatePL003()
    ctx = RequestContext(
        session_id="test-session",
        user_id="user1",
        raw_prompt="Send financial report",
        tool_calls=[{"name": "send_email", "arguments": {"to": "cfo@company.com", "subject": "Report", "body": "Data"}}],
        metadata={"domain3_user_role": "user"},
    )
    verdict = control.evaluate(ctx)
    assert verdict.status == "escalate"
    assert verdict.risk_score == 0.7
    assert "requires human approval" in verdict.reason.lower()


def test_pl003_sensitive_tool_with_approval_passes():
    control = SensitiveToolGatePL003()
    ctx = RequestContext(
        session_id="test-session",
        user_id="user1",
        raw_prompt="Send financial report",
        tool_calls=[{"name": "send_email", "arguments": {"to": "cfo@company.com", "subject": "Report", "body": "Data"}}],
        metadata={
            "domain3_user_role": "user",
            "domain3_approved_actions": ["send_email"],
        },
    )
    verdict = control.evaluate(ctx)
    assert verdict.status == "pass"
    assert verdict.risk_score == 0.0


def test_pl003_nonsensitive_tool_passes():
    control = SensitiveToolGatePL003()
    ctx = RequestContext(
        session_id="test-session",
        user_id="user1",
        raw_prompt="Calculate expression",
        tool_calls=[{"name": "calculator", "arguments": {"expression": "100 / 4"}}],
    )
    verdict = control.evaluate(ctx)
    assert verdict.status == "pass"
    assert verdict.risk_score == 0.0


