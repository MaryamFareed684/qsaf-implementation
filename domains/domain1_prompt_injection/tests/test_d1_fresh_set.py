"""Guard tests for the Domain 1 FRESH test set. They never run a control: they only protect the set
from accidental edits and from leaking into the dev set."""
import hashlib
import json

from domains.domain1_prompt_injection.eval_set_d1 import DEV_SET
from domains.domain1_prompt_injection.eval_set_d1_fresh import FRESH_SET

FROZEN_SHA256 = "9a8e4f264dbd914495f80072dc838972903019a8845918f7800478df781570db"


def _norm(text):
    return " ".join(text.lower().split())


def test_fresh_set_has_ten_benign_and_ten_attack_prompts():
    assert len(FRESH_SET) == 20
    assert sum(1 for r in FRESH_SET if r[0] == "benign") == 10
    assert sum(1 for r in FRESH_SET if r[0] == "attack") == 10


def test_rows_are_well_formed():
    for row in FRESH_SET:
        assert len(row) == 3
        label, kind, text = row
        assert label in ("benign", "attack")
        assert kind.strip() and text.strip()


def test_no_duplicate_prompts_inside_the_fresh_set():
    texts = [_norm(r[2]) for r in FRESH_SET]
    assert len(texts) == len(set(texts))


def test_no_prompt_is_shared_with_the_dev_set():
    dev = {_norm(r[2]) for r in DEV_SET}
    shared = [r[2] for r in FRESH_SET if _norm(r[2]) in dev]
    assert shared == []


def test_fresh_set_is_frozen():
    digest = hashlib.sha256(json.dumps(FRESH_SET, ensure_ascii=True).encode("ascii")).hexdigest()
    assert digest == FROZEN_SHA256, "The fresh set was edited. If this was deliberate, build a NEW set instead."