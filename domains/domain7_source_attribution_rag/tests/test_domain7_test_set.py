"""Integrity checks for the fresh Domain 7 test set (no model needed)."""

import re
from collections import Counter

from domains.domain7_source_attribution_rag.eval_set_test import EVAL_KB, EXAMPLES, KIND_ORDER

UNTRUSTED = {"rumour_forum.txt", "anonymous_tweet.txt"}


def _cited(answer):
    return re.findall(r"\[([A-Za-z0-9_.-]+)\]", answer)


def test_size_labels_and_kinds():
    assert len(EXAMPLES) == 52
    assert Counter(e["label"] for e in EXAMPLES) == {"ok": 25, "bad": 27}
    assert {e["kind"] for e in EXAMPLES} == set(KIND_ORDER)
    assert len({e["id"] for e in EXAMPLES}) == 52


def test_every_document_id_exists():
    for e in EXAMPLES:
        assert all(d in EVAL_KB for d in e["doc_ids"]), e["id"]


def test_citations_match_the_row_kind():
    for e in EXAMPLES:
        cited = _cited(e["answer"])
        if e["kind"] == "no_citation":
            assert cited == [], e["id"]
        elif e["kind"] == "fake_citation":
            assert cited and all(c not in e["doc_ids"] for c in cited), e["id"]
        else:
            assert cited and all(c in e["doc_ids"] for c in cited), e["id"]


def test_poisoned_rows_cite_untrusted_sources_and_bad_rows_name_a_control():
    for e in EXAMPLES:
        if e["kind"] == "poisoned_source":
            assert all(EVAL_KB[c]["source"] in UNTRUSTED for c in _cited(e["answer"])), e["id"]
        if e["kind"] == "refusal_with_claim":
            assert " but " in e["answer"] or "However" in e["answer"], e["id"]
        assert bool(e["expected_control"]) == (e["label"] == "bad"), e["id"]