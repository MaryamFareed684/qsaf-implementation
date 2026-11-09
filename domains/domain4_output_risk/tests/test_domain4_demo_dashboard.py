"""
Tests for the Domain 4 demo runner and the Domain 4 dashboard tab.

The dashboard test replaces `streamlit` with a small fake, so it runs offline
and does not need a browser. It checks our logic (which widgets are drawn, what
happens when buttons are clicked), not Streamlit's own rendering.

Run (PowerShell, repo root):
    pytest domains/domain4_output_risk/tests/test_domain4_demo_dashboard.py -v
"""

import importlib
import sys
from unittest.mock import MagicMock, patch

import pytest

from core.models import Verdict
from domains.domain4_output_risk.controls import ALL_CONTROLS
from domains.domain4_output_risk.demo_domain4 import EXAMPLES, SEVERITY, run_domain4

EXAMPLE_NAMES = list(EXAMPLES)


# ------------------------------------------------------------------ demo runner
@pytest.mark.parametrize("name", EXAMPLE_NAMES)
def test_every_example_runs_all_controls(name):
    prompt, reply = EXAMPLES[name]
    verdicts, worst = run_domain4(prompt, reply)
    assert len(verdicts) == len(ALL_CONTROLS) == 7
    assert all(isinstance(v, Verdict) for v in verdicts)
    assert worst in verdicts
    assert [v.control_id for v in verdicts] == [c.control_id for c in ALL_CONTROLS]


def test_benign_example_is_not_blocked():
    verdicts, worst = run_domain4(*EXAMPLES["Benign reply"])
    assert worst.status == "pass"


def test_harmful_example_is_caught_by_or_001():
    verdicts, worst = run_domain4(*EXAMPLES["Harmful reply"])
    or001 = next(v for v in verdicts if v.control_id == "OR-001")
    assert or001.status in ("block", "escalate")
    assert SEVERITY[worst.status] >= SEVERITY["block"]


def test_worst_verdict_is_most_severe():
    verdicts, worst = run_domain4(*EXAMPLES["Harmful reply"])
    assert all(
        (SEVERITY[worst.status], worst.risk_score) >= (SEVERITY[v.status], v.risk_score) for v in verdicts
    )


def test_empty_reply_does_not_crash():
    verdicts, worst = run_domain4("hello", "")
    assert len(verdicts) == 7


def test_one_broken_control_does_not_stop_the_others():
    class Boom:
        control_id = "OR-X"
        def safe_evaluate(self, ctx):
            return Verdict("OR-X", "d", "warn", 0.5, "Control raised an internal error: boom", {})
    from domains.domain4_output_risk import demo_domain4
    with patch.object(demo_domain4, "ALL_CONTROLS", [Boom(), *ALL_CONTROLS]):
        verdicts, _ = demo_domain4.run_domain4("p", "The capital of France is Paris.")
    assert len(verdicts) == 8


def test_no_sensitive_text_in_or_001_audit_fields():
    prompt, reply = EXAMPLES["Harmful reply"]
    verdicts, _ = run_domain4(prompt, reply)
    or001 = next(v for v in verdicts if v.control_id == "OR-001")
    assert reply.lower() not in (or001.reason + str(or001.evidence)).lower()


# ------------------------------------------------------------- dashboard (faked)
class FakeStreamlit:
    """Records calls and lets a test decide which buttons are 'clicked'."""

    def __init__(self, clicked=(), state=None):
        self.session_state = dict(state or {})
        self.clicked = set(clicked)
        self.calls = []          # (method, text)
        self.on_click = {}       # key -> (callback, args)

    # --- widgets
    def text_area(self, label, key=None, **kw):
        self.calls.append(("text_area", key))
        return self.session_state.get(key, "")

    def button(self, label, key=None, on_click=None, args=(), **kw):
        self.calls.append(("button", key))
        if on_click:
            self.on_click[key] = (on_click, args)
        return key in self.clicked

    def columns(self, spec):
        n = spec if isinstance(spec, int) else len(spec)
        cols = []
        for _ in range(n):
            col = MagicMock()
            col.button.side_effect = lambda label, key=None, on_click=None, args=(), **kw: self.button(
                label, key=key, on_click=on_click, args=args
            )
            cols.append(col)
        return cols

    def expander(self, title, expanded=False):
        self.calls.append(("expander", title))
        return MagicMock()

    # --- plain output
    def __getattr__(self, name):
        def recorder(*a, **kw):
            self.calls.append((name, a[0] if a else None))
        return recorder

    def titles(self, method):
        return [t for m, t in self.calls if m == method]


def load_dashboard(fake):
    """Import dashboard_section with `streamlit` replaced by the fake."""
    sys.modules.pop("domains.domain4_output_risk.dashboard_section", None)
    with patch.dict(sys.modules, {"streamlit": fake}):
        module = importlib.import_module("domains.domain4_output_risk.dashboard_section")
        return module


def test_dashboard_exposes_the_agreed_function():
    module = load_dashboard(FakeStreamlit())
    assert callable(module.render_domain4_tab)


def test_dashboard_draws_two_boxes_example_buttons_and_run():
    fake = FakeStreamlit()
    module = load_dashboard(fake)
    module.render_domain4_tab()
    assert fake.titles("text_area") == ["d4_prompt", "d4_reply"]
    buttons = fake.titles("button")
    assert "d4_run" in buttons
    assert len([b for b in buttons if b.startswith("d4_example_")]) == len(EXAMPLES)


def test_all_widget_keys_are_namespaced():
    fake = FakeStreamlit()
    module = load_dashboard(fake)
    module.render_domain4_tab()
    keys = fake.titles("text_area") + fake.titles("button")
    assert keys and all(k.startswith("d4_") for k in keys)


@pytest.mark.parametrize("name", EXAMPLE_NAMES)
def test_example_button_fills_both_boxes(name):
    fake = FakeStreamlit()
    module = load_dashboard(fake)
    module.render_domain4_tab()
    callback, args = fake.on_click[f"d4_example_{name}"]
    callback(*args)                                  # what Streamlit does on click
    prompt, reply = EXAMPLES[name]
    assert fake.session_state["d4_prompt"] == prompt
    assert fake.session_state["d4_reply"] == reply


def test_run_with_empty_reply_shows_warning_not_result():
    fake = FakeStreamlit(clicked={"d4_run"})
    module = load_dashboard(fake)
    module.render_domain4_tab()
    assert fake.titles("warning")
    assert "d4_result" not in fake.session_state
    assert not fake.titles("expander")


def test_run_shows_one_expander_per_control():
    prompt, reply = EXAMPLES["Harmful reply"]
    fake = FakeStreamlit(clicked={"d4_run"}, state={"d4_prompt": prompt, "d4_reply": reply})
    module = load_dashboard(fake)
    module.render_domain4_tab()
    expanders = fake.titles("expander")
    assert len(expanders) == 7
    assert any("OR-001" in t and ("BLOCK" in t or "ESCALATE" in t) for t in expanders)


def test_benign_run_shows_pass_for_or_001():
    prompt, reply = EXAMPLES["Benign reply"]
    fake = FakeStreamlit(clicked={"d4_run"}, state={"d4_prompt": prompt, "d4_reply": reply})
    module = load_dashboard(fake)
    module.render_domain4_tab()
    assert any("OR-001" in t and "PASS" in t for t in fake.titles("expander"))
