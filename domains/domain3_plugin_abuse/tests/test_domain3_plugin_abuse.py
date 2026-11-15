"""
tests/test_domain3_plugin_abuse.py

Runs this domain's payloads.csv through this domain's controls only.
Every teammate should be able to run:
    pytest domains/domain3_plugin_abuse/tests/test_domain3_plugin_abuse.py
and see their own domain's results, independent of everyone else's work.
"""

import csv
import json
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
    tool_calls = []
    if payload.get("tool_name"):
        args_str = payload.get("tool_args", "").strip()
        args = json.loads(args_str) if args_str else {}
        tool_calls.append({"name": payload["tool_name"], "arguments": args})

    metadata = {}
    if payload.get("notes") and "analyst" in payload["notes"].lower():
        metadata["domain3_user_role"] = "analyst"
    if payload.get("notes") and ("with human approval" in payload["notes"].lower() or "with approval" in payload["notes"].lower()):
        metadata["domain3_approved_actions"] = [payload["tool_name"]]



    ctx = RequestContext(
        session_id=f"test-payload-{abs(hash(payload['prompt'])) % 10000}",
        user_id="test-user",
        raw_prompt=payload["prompt"],
        tool_calls=tool_calls,
        metadata=metadata,
    )
    verdicts = [c.safe_evaluate(ctx) for c in ALL_CONTROLS]
    assert all(v.status in ("pass", "warn", "block", "escalate") for v in verdicts)

    expected = payload.get("expected")
    if expected == "malicious":
        assert any(v.status in ("block", "escalate") for v in verdicts), (
            f"Expected malicious payload to be blocked/escalated: {payload['prompt']}"
        )
    elif expected == "benign":
        assert all(v.status == "pass" for v in verdicts), (
            f"Expected benign payload to pass all controls: {payload['prompt']} -> {[v.status for v in verdicts]}"
        )



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




# ---- Regression tests added after Day 1 review (PL-002 false alarms and gaps) ----
from core.models import RequestContext as _RC
from domains.domain3_plugin_abuse.controls import ALL_CONTROLS as _ALL


def _pl002(tool, **args):
    control = [c for c in _ALL if c.control_id == "PL-002"][0]
    ctx = _RC(session_id="reg-1", user_id="u1", raw_prompt="test",
              tool_calls=[{"name": tool, "arguments": args}])
    return control.evaluate(ctx)


def test_pl002_rm_without_f_blocks():
    assert _pl002("system_command", command="rm -r /home/user").status == "block"


def test_pl002_word_perform_is_not_rm():
    v = _pl002("send_email", to="a@b.com", subject="Report", body="Please perform -r analysis")
    assert v.status == "pass"


def test_pl002_semicolon_in_normal_text_passes():
    v = _pl002("send_email", to="a@b.com", subject="Hi", body="Thanks; cat pictures attached")
    assert v.status == "pass"


def test_pl002_sql_semicolon_passes():
    assert _pl002("database_query", query="SELECT name FROM students;").status == "pass"


def test_pl002_chained_whoami_warns():
    assert _pl002("system_command", command="ls; whoami").status == "warn"


def test_pl002_pipe_to_shell_warns():
    assert _pl002("system_command", command="cat file | sh").status == "warn"


# --- PL-004 Unit Tests ---

from domains.domain3_plugin_abuse.controls.pl_004_tool_anomaly import ToolAnomalyPL004


def test_pl004_normal_duration_passes():
    control = ToolAnomalyPL004()
    ctx = RequestContext(
        session_id="test-session",
        user_id="u1",
        raw_prompt="calc",
        tool_calls=[{"name": "calculator", "arguments": {"expression": "2+2"}, "duration_ms": 100}],
    )
    verdict = control.evaluate(ctx)
    assert verdict.status == "pass"
    assert verdict.risk_score == 0.0


def test_pl004_missing_duration_passes():
    control = ToolAnomalyPL004()
    ctx = RequestContext(
        session_id="test-session",
        user_id="u1",
        raw_prompt="calc",
        tool_calls=[{"name": "calculator", "arguments": {"expression": "2+2"}}],
    )
    verdict = control.evaluate(ctx)
    assert verdict.status == "pass"


def test_pl004_hard_limit_exceeded_blocks():
    control = ToolAnomalyPL004()
    ctx = RequestContext(
        session_id="test-session",
        user_id="u1",
        raw_prompt="calc",
        tool_calls=[{"name": "calculator", "arguments": {"expression": "2+2"}, "duration_ms": 15000}],
    )
    verdict = control.evaluate(ctx)
    assert verdict.status == "block"
    assert verdict.risk_score >= 0.9


def test_pl004_z_score_anomaly_warns():
    control = ToolAnomalyPL004()
    control.reset_history()
    for _ in range(10):
        control.evaluate(
            RequestContext(
                session_id="s-bench",
                user_id="u1",
                raw_prompt="bench",
                tool_calls=[{"name": "read_file", "arguments": {"filepath": "doc.txt"}, "duration_ms": 100}],
            )
        )
    ctx_anom = RequestContext(
        session_id="s-bench",
        user_id="u1",
        raw_prompt="bench",
        tool_calls=[{"name": "read_file", "arguments": {"filepath": "doc.txt"}, "duration_ms": 2500}],
    )
    verdict = control.evaluate(ctx_anom)
    assert verdict.status == "warn"


# --- PL-005 Unit Tests ---

from domains.domain3_plugin_abuse.controls.pl_005_usage_correlation import UsageCorrelationPL005


def test_pl005_matching_intent_passes():
    control = UsageCorrelationPL005()
    ctx = RequestContext(
        session_id="s1",
        user_id="u1",
        raw_prompt="Calculate 25 * 4",
        tool_calls=[{"name": "calculator", "arguments": {"expression": "25 * 4"}}],
    )
    verdict = control.evaluate(ctx)
    assert verdict.status == "pass"
    assert verdict.risk_score == 0.0


def test_pl005_uncorrelated_sensitive_tool_escalates():
    control = UsageCorrelationPL005()
    ctx = RequestContext(
        session_id="s1",
        user_id="u1",
        raw_prompt="Summarize this article",
        tool_calls=[{"name": "send_email", "arguments": {"to": "a@b.com", "subject": "Hi", "body": "text"}}],
    )
    verdict = control.evaluate(ctx)
    assert verdict.status == "escalate"
    assert verdict.risk_score >= 0.7


def test_pl005_uncorrelated_normal_tool_warns():
    control = UsageCorrelationPL005()
    ctx = RequestContext(
        session_id="s1",
        user_id="u1",
        raw_prompt="Tell me a joke",
        tool_calls=[{"name": "calculator", "arguments": {"expression": "1+1"}}],
    )
    verdict = control.evaluate(ctx)
    assert verdict.status == "warn"


# --- PL-006 Unit Tests ---

from domains.domain3_plugin_abuse.controls.pl_006_rate_limiter import RateLimiterPL006


def test_pl006_single_call_passes():
    control = RateLimiterPL006()
    ctx = RequestContext(
        session_id="rate-test-1",
        user_id="u1",
        raw_prompt="search",
        tool_calls=[{"name": "web_search", "arguments": {"query": "weather"}}],
    )
    verdict = control.evaluate(ctx)
    assert verdict.status == "pass"


def test_pl006_burst_30_calls_blocks():
    # Reviewer's exact test scenario
    control = RateLimiterPL006()
    control.reset_history()
    ctx = RequestContext(
        session_id="rate-test-burst",
        user_id="u1",
        raw_prompt="burst",
        tool_calls=[{"name": "calculator", "arguments": {"expression": f"{i}+1"}} for i in range(30)],
    )
    verdict = control.evaluate(ctx)
    assert verdict.status == "block"
    assert verdict.risk_score >= 0.9
    assert "rate limit exceeded" in verdict.reason.lower()


def test_pl006_different_sessions_isolated():
    control = RateLimiterPL006()
    control.reset_history()
    ctx1 = RequestContext(
        session_id="session-a",
        user_id="u1",
        raw_prompt="burst",
        tool_calls=[{"name": "calculator", "arguments": {"expression": "1+1"}} for _ in range(30)],
    )
    assert control.evaluate(ctx1).status == "block"

    ctx2 = RequestContext(
        session_id="session-b",
        user_id="u2",
        raw_prompt="normal",
        tool_calls=[{"name": "calculator", "arguments": {"expression": "1+1"}}],
    )
    assert control.evaluate(ctx2).status == "pass"


# --- PL-007 Unit Tests ---

from domains.domain3_plugin_abuse.controls.pl_007_session_terminator import SessionTerminatorPL007


def test_pl007_strike_accumulation_and_termination():
    control = SessionTerminatorPL007()
    control.reset_history()

    # Strike 1: pass (good standing)
    ctx1 = RequestContext(
        session_id="term-s1",
        user_id="u1",
        raw_prompt="attack 1",
        tool_calls=[{"name": "delete_file", "arguments": {"filepath": "/etc/passwd"}}],
    )
    v1 = control.evaluate(ctx1)
    assert v1.status == "pass"

    # Strike 2: warn
    ctx2 = RequestContext(
        session_id="term-s1",
        user_id="u1",
        raw_prompt="attack 2",
        tool_calls=[{"name": "delete_file", "arguments": {"filepath": "/var/log"}}],
    )
    v2 = control.evaluate(ctx2)
    assert v2.status == "warn"

    # Strike 3: block and terminate session
    ctx3 = RequestContext(
        session_id="term-s1",
        user_id="u1",
        raw_prompt="attack 3",
        tool_calls=[{"name": "delete_file", "arguments": {"filepath": "/tmp/data"}}],
    )
    v3 = control.evaluate(ctx3)
    assert v3.status == "block"
    assert v3.risk_score == 1.0
    assert v3.evidence.get("terminate_session") is True


def test_pl005_word_perform_does_not_match_rm():
    control = UsageCorrelationPL005()
    # "perform" contains "rm", but is NOT the word "rm"
    ctx = RequestContext(
        session_id="s-regex",
        user_id="u1",
        raw_prompt="Please perform a routine health check on the server",
        tool_calls=[{"name": "delete_file", "arguments": {"filepath": "/var/log/syslog"}}],
    )
    verdict = control.evaluate(ctx)
    # Because "perform" does not match "rm", delete_file is correctly flagged as uncorrelated sensitive tool
    assert verdict.status == "escalate"
    assert "intent" in verdict.reason.lower()


def test_pl007_unapproved_sensitive_tool_is_not_a_strike():
    control = SessionTerminatorPL007()
    control.reset_history()
    ctx = RequestContext(
        session_id="benign-email-session",
        user_id="user1",
        raw_prompt="Send meeting minutes to team",
        tool_calls=[{"name": "send_email", "arguments": {"to": "team@co.com", "subject": "Minutes", "body": "Notes"}}],
        metadata={"domain3_user_role": "user"},
    )
    # Routine escalation should NOT be treated as a security breach strike
    for _ in range(3):
        v = control.evaluate(ctx)
        assert v.status == "pass"
        assert v.evidence.get("strike_count") == 0


def test_pl007_isolated_session_strikes():
    control = SessionTerminatorPL007()
    control.reset_history()
    ctx_bad = RequestContext(
        session_id="attacker-session",
        user_id="bad_user",
        raw_prompt="drop db",
        tool_calls=[{"name": "system_command", "arguments": {"cmd": "rm -rf /"}}],
    )
    control.evaluate(ctx_bad)
    control.evaluate(ctx_bad)

    ctx_good = RequestContext(
        session_id="innocent-session",
        user_id="good_user",
        raw_prompt="search docs",
        tool_calls=[{"name": "web_search", "arguments": {"query": "python"}}],
    )
    v_good = control.evaluate(ctx_good)
    assert v_good.status == "pass"
    assert v_good.evidence.get("strike_count") == 0


def test_pl007_strike_window_expiration():
    import time
    control = SessionTerminatorPL007()
    control.reset_history()
    # Seed expired strikes (older than 300s window)
    control._strikes["expire-session"] = [time.time() - 400, time.time() - 350]

    ctx = RequestContext(
        session_id="expire-session",
        user_id="u1",
        raw_prompt="attack",
        tool_calls=[{"name": "delete_file", "arguments": {"filepath": "/etc/shadow"}}],
    )
    verdict = control.evaluate(ctx)
    # Expired strikes pruned, only 1 new active strike -> session in good standing (pass)
    assert verdict.status == "pass"
    assert verdict.evidence.get("strike_count") == 1


def test_pl007_pipeline_short_circuit_accumulation():
    """Verify PL-007 at index 0 accumulates strikes across orchestrator runs."""
    from core.orchestrator import Orchestrator
    from domains.domain3_plugin_abuse.controls import ALL_CONTROLS as D3_CONTROLS

    orch = Orchestrator()
    for c in D3_CONTROLS:
        if hasattr(c, "reset_history"):
            c.reset_history()
        orch.register(c)

    ctx_attack = RequestContext(
        session_id="pipeline-strike-sess",
        user_id="u1",
        raw_prompt="delete system log",
        tool_calls=[{"name": "delete_file", "arguments": {"filepath": "/var/log/sys.log"}}],
    )

    # Run 1: Strike 1 recorded by PL-007, request blocked downstream by PL-001
    res1 = orch.run_layer("execution", ctx_attack)
    assert res1.final_status == "block"

    # Run 2: Strike 2 recorded by PL-007, request blocked downstream
    res2 = orch.run_layer("execution", ctx_attack)
    assert res2.final_status == "block"

    # Run 3: Strike 3 recorded by PL-007 -> terminated on PL-007 immediately!
    res3 = orch.run_layer("execution", ctx_attack)
    assert res3.final_status == "block"
    pl007_verdict = [v for v in res3.verdicts if v.control_id == "PL-007"][0]
    assert pl007_verdict.status == "block"
    assert pl007_verdict.evidence.get("terminate_session") is True


