"""Tests for the Domain 3 dashboard helpers (no browser needed)."""

import pytest

from domains.domain3_plugin_abuse import dashboard_section as ds


@pytest.fixture(autouse=True)
def _fresh_history():
    ds.reset_state()
    yield
    ds.reset_state()


def _run(index):
    preset = ds.PRESETS[index]
    final, verdicts, _ = ds.evaluate_request(
        preset["prompt"], preset["tool_calls"], preset["metadata"], preset["session_id"])
    return final, verdicts


def test_all_seven_controls_report():
    _, verdicts = _run(0)
    assert {v.control_id for v in verdicts} == {f"PL-00{i}" for i in range(1, 8)}


@pytest.mark.parametrize("index", [0, 4])
def test_benign_presets_are_not_blocked(index):
    final, _ = _run(index)
    assert final.status in ("pass", "warn"), (ds.PRESETS[index]["title"], final.status)


@pytest.mark.parametrize("index", [1, 2, 3, 5])
def test_attack_presets_are_stopped(index):
    final, _ = _run(index)
    assert final.status in ("block", "escalate"), (ds.PRESETS[index]["title"], final.status)


def test_reset_clears_the_history_between_runs():
    first, _ = _run(0)
    ds.reset_state()
    second, _ = _run(0)
    assert first.status == second.status