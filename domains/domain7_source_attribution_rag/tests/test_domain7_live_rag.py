"""Tests for the live RAG helpers (no network, no key and no PDF needed)."""

import types
import uuid

import numpy as np
import pytest

from core.models import RequestContext
from domains.domain7_source_attribution_rag import live_rag
from domains.domain7_source_attribution_rag.controls.sa_007_auto_disable import reset_all
from domains.domain7_source_attribution_rag.demo_domain7 import run_pipeline


@pytest.fixture(autouse=True)
def _clean_sa007_state():
    reset_all()
    yield
    reset_all()


def test_extract_text_reads_txt_and_rejects_bad_input():
    text = " ".join(f"word{i}" for i in range(30)).encode("utf-8")
    assert live_rag.extract_text("a.txt", text).startswith("word0")
    with pytest.raises(live_rag.LiveRagError):
        live_rag.extract_text("a.txt", b"too short")
    with pytest.raises(live_rag.LiveRagError):
        live_rag.extract_text("a.docx", text)


def test_chunk_text_keeps_every_word_and_respects_the_limit():
    sentences = " ".join(f"This is sentence number {i} of the test." for i in range(40))
    chunks = live_rag.chunk_text(sentences, max_words=30)
    assert all(len(c.split()) <= 30 for c in chunks)
    assert " ".join(chunks).split() == sentences.split()
    no_punctuation = " ".join(f"w{i}" for i in range(100))
    assert [len(p.split()) for p in live_rag.chunk_text(no_punctuation, max_words=40)] == [40, 40, 20]


def test_retrieve_from_embeddings_ranks_by_similarity_and_labels_documents():
    chunks = ["alpha", "bravo", "charlie"]
    emb = np.array([[1.0, 0.0], [0.0, 1.0], [0.6, 0.8]])
    docs = live_rag.retrieve_from_embeddings(np.array([0.0, 1.0]), chunks, emb, "upload_trusted", k=2)
    assert [d["doc_id"] for d in docs] == ["up-2", "up-3"]
    assert docs[0]["source"] == "upload_trusted" and docs[0]["text"] == "bravo"
    assert docs[0]["score"] == 1.0 and docs[1]["score"] == 0.8


def test_build_messages_marks_passages_as_data_and_requires_citations():
    docs = [{"doc_id": "up-3", "source": "s", "text": "Refunds take 14 days.", "score": 0.9}]
    messages = live_rag.build_messages("How long?", docs)
    assert messages[0]["role"] == "system" and "untrusted data" in messages[0]["content"]
    assert live_rag.REFUSAL_SENTENCE in messages[0]["content"]
    assert '<passage id="up-3">Refunds take 14 days.</passage>' in messages[1]["content"]
    assert "Question: How long?" in messages[1]["content"]


def test_clean_answer_splits_grouped_citations_and_strips_markdown():
    raw = "**Refunds** take 14 days [up-2, up-5].\n\nThey go to the card [up-2]."
    assert live_rag.clean_answer(raw) == "Refunds take 14 days [up-2][up-5]. They go to the card [up-2]."


def _fake_client(content):
    def create(**kwargs):
        return types.SimpleNamespace(choices=[types.SimpleNamespace(message=types.SimpleNamespace(content=content))])
    return types.SimpleNamespace(chat=types.SimpleNamespace(completions=types.SimpleNamespace(create=create)))


def test_ask_groq_returns_cleaned_text_and_reports_problems(monkeypatch):
    messages = [{"role": "user", "content": "x"}]
    assert live_rag.ask_groq(messages, client=_fake_client("Yes [up-1, up-2].")) == "Yes [up-1][up-2]."
    with pytest.raises(live_rag.LiveRagError):
        live_rag.ask_groq(messages, client=_fake_client("   "))

    def boom(**kwargs):
        raise RuntimeError("model not found")
    broken = types.SimpleNamespace(chat=types.SimpleNamespace(completions=types.SimpleNamespace(create=boom)))
    with pytest.raises(live_rag.LiveRagError):
        live_rag.ask_groq(messages, client=broken)

    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    with pytest.raises(live_rag.LiveRagError):
        live_rag.ask_groq(messages)


def test_list_models_sorts_ids():
    models = types.SimpleNamespace(list=lambda: types.SimpleNamespace(
        data=[types.SimpleNamespace(id="b"), types.SimpleNamespace(id="a")]))
    assert live_rag.list_models(client=types.SimpleNamespace(models=models)) == ["a", "b"]


ANSWER = "Refunds are possible within 14 days of purchase [up-2]."


def test_tamper_modes():
    assert live_rag.tamper_answer(ANSWER, live_rag.TAMPER_NONE) == ANSWER
    assert live_rag.tamper_answer(ANSWER, live_rag.TAMPER_NUMBER) == "Refunds are possible within 31 days of purchase [up-2]."
    assert "founded in 1987" in live_rag.tamper_answer(ANSWER, live_rag.TAMPER_INVENT)
    assert live_rag.tamper_answer(ANSWER, live_rag.TAMPER_UNCITED) == "Refunds are possible within 14 days of purchase."
    assert live_rag.tamper_answer(ANSWER, live_rag.TAMPER_FAKE).endswith("[up-999]")
    assert live_rag.tamper_answer("No digits here [up-1].", live_rag.TAMPER_NUMBER).endswith("A fee of 99 dollars also applies.")


DOC = {"doc_id": "up-2", "source": "upload_trusted", "score": 0.9,
       "text": "Refunds are possible within 14 days of purchase. The money is returned to the original payment method."}


def _run(answer, source="upload_trusted"):
    ctx = RequestContext(uuid.uuid4().hex, "u", "How many days do I have to ask for a refund?",
                         retrieved_docs=[dict(DOC, source=source)], agent_output=answer)
    return run_pipeline(ctx, log=False)


def _by_control(answer, source="upload_trusted"):
    return {v.control_id: v for v in _run(answer, source)[1]}


def test_tampered_answers_are_flagged_by_the_expected_controls():
    final, _ = _run(ANSWER)
    assert final.evidence["blocked_by"] is None
    assert _by_control(live_rag.tamper_answer(ANSWER, live_rag.TAMPER_NUMBER))["SA-003"].status != "pass"
    assert _by_control(live_rag.tamper_answer(ANSWER, live_rag.TAMPER_FAKE))["SA-005"].status == "block"
    assert _by_control(live_rag.tamper_answer(ANSWER, live_rag.TAMPER_UNCITED))["SA-005"].status == "warn"
    assert _by_control(live_rag.tamper_answer(ANSWER, live_rag.TAMPER_INVENT))["SA-002"].status != "pass"


def test_untrusted_upload_label_is_blocked_by_source_trust():
    assert _by_control(ANSWER, source="upload_untrusted")["SA-006"].status == "block"