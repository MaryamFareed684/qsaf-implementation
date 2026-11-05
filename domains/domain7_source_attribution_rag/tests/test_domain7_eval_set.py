"""Integrity checks for the Domain 7 evaluation set (no model needed)."""

import re
from collections import Counter

from domains.domain7_source_attribution_rag.eval_set import EVAL_KB, EXAMPLES, KIND_ORDER

UNTRUSTED = {"anonymous_blog.txt", "social_media_post.txt"}


def _cited(answer):
    return re.findall(r"\[([A-Za-z0-9_.-]+)\]", answer)


def test_size_labels_and_kinds():
    assert len(EXAMPLES) == 60
    assert Counter(e["label"] for e in EXAMPLES) == {"ok": 28, "bad": 32}
    assert {e["kind"] for e in EXAMPLES} == set(KIND_ORDER)
    assert len({e["id"] for e in EXAMPLES}) == 60


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


def test_poisoned_rows_cite_an_untrusted_source_and_bad_rows_name_a_control():
    for e in EXAMPLES:
        if e["kind"] == "poisoned_source":
            assert all(EVAL_KB[c]["source"] in UNTRUSTED for c in _cited(e["answer"])), e["id"]
        assert bool(e["expected_control"]) == (e["label"] == "bad"), e["id"]