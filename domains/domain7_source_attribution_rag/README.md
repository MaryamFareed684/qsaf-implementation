# Domain 7: Source Attribution & RAG Monitoring

**Status:** implemented (SA-001 to SA-007), tested, evaluated on a labelled dev set and a fresh test set.
Layer for all seven controls: `egress`.

## 1. Stage 1: understanding the domain

**What it protects against.** In a Retrieval-Augmented Generation (RAG) system an answer is built from
retrieved documents. This domain makes every answer traceable to its sources and checks the answer
against them. Without it nobody can tell a grounded answer from an invented one.

**Failure sources** (who or what causes the problem):

| # | Failure | Source |
|---|---|---|
| 1 | Answer contains facts that are in no document (unsupported claim) | the LLM |
| 2 | Answer contradicts the document (wrong number, negation) | the LLM |
| 3 | "Hallucination" is the umbrella term for 1 and 2 | the LLM |
| 4 | No attribution: the answer cannot be traced to a document | the LLM and the system (provenance not recorded) |
| 5 | Faithful answer built on a poisoned or low-trust document | the document |
| 6 | The wrong documents were retrieved for the question | the retrieval step |

A check that compares the answer with the retrieved text catches 1 and 2. It is blind to 5 and 6, which
is why SA-004 (retrieval relevance) and SA-006 (source trust) exist.

**Pipeline layer.** All controls run in `egress`: the answer (`ctx.agent_output`) only exists after the
LLM has responded, and `egress` is the only post-LLM layer in the shared orchestrator. SA-001 and SA-006
could run earlier, but SA-006 needs the answer's citations, so all stay together at `egress`.

**Inputs:** `ctx.retrieved_docs` (dicts with `doc_id`, `source`, `text`), `ctx.agent_output`,
`ctx.raw_prompt`, and `ctx.metadata["prior_verdicts"]` (set by the caller, never mutated by a control).

## 2. Controls (Control Book IDs, no extra control added)

| ID | Control Book name | What this implementation checks | Statuses |
|---|---|---|---|
| SA-001 | Track document source in RAG systems | every retrieved doc has `doc_id` and `source`; the source list goes into `evidence` and so into the audit log | pass / warn |
| SA-002 | Compare LLM response to top-K retrieved docs | each answer sentence vs the retrieved sentences (embeddings plus a lexical fallback) | pass / warn / block |
| SA-003 | Calculate hallucination likelihood score | unsupported sentences (from SA-002) + numbers/names found in no cited doc + contradictions with the source wording | pass / warn / block |
| SA-004 | Flag mismatch between retrieval and output | are the retrieved docs relevant to the question at all | pass / warn |
| SA-005 | Log and alert for non-attributable responses | answer must cite documents that were really retrieved | pass / warn / block |
| SA-006 | Embed source trust rating into response | trust level of the sources the answer relies on; a ready-made `trust_footer` is placed in `evidence` | pass / warn / block |
| SA-007 | Auto-disable RAG pipeline upon anomaly | session-level: 3 blocked requests in the last 5 disable RAG until an operator resets the session | pass / warn / block |

Refusal handling ("I could not find that in the documents") is built into SA-002/003/004/005 through
`common.py` and the `refusal` policy section, instead of adding an eighth control.

## 3. Design decisions

- **Thresholds come from measurements, not from papers.** `calibrate_domain7.py` sets SA-002's support
  threshold (0.694) and SA-004's model and threshold (multi-qa-MiniLM-L6-cos-v1, 0.34) on the dev set.
  Weights, risk values and window sizes are heuristic and are labelled as such in `policy.yaml`.
- **SA-003 reads SA-002's result** from `ctx.metadata["prior_verdicts"]` (the convention Domain 2's RC-006
  uses) instead of recomputing it: no second embedding pass and no chance of two disagreeing answers.
  If SA-002's verdict is missing, SA-003 warns with a clear reason and never crashes.
- **No private log files.** Controls put what an auditor needs into `Verdict.evidence`; the shared logger
  writes it to the audit log (checked by an integration test).
- **SA-005: block on a fake citation, warn on no citation.** A citation to a document that was never
  retrieved is a fabricated attribution: it gives the reader false assurance. A missing citation only
  means the answer cannot be traced.
- **SA-006: a block is capped to warn when the answer cites nothing.** Without a citation we cannot know
  which retrieved document the answer used, and one untrusted document in the top-K must not kill an
  answer that never used it.
- **SA-007 is latched and counts only blocks.** It stays disabled until `reset_session()` is called so an
  attacker cannot recover the pipeline by sending a few harmless requests. Only blocked requests count:
  off-topic questions (an SA-004 warning) are user behaviour, not evidence of an attack, and counting
  them would lock honest users out.
- **SA-003 contradiction check (negation / antonym pairs) is deliberately weak** (weight 0.2, below the
  0.25 warn threshold): as a warning it caused five false alarms on correct paraphrases in the dev set.
  Alone it only records evidence; together with another signal it still raises a warning.
- **Refusals are exempt only when strict:** short, no digits, and no "but / however". A refusal that
  hides an invented claim is still checked (tested, and 3/3 caught in the fresh set).
- **The shared orchestrator does not fill `prior_verdicts`**, so SA-003 and SA-007 get no earlier
  verdicts through it. `demo_domain7.run_pipeline` fills them itself, runs all seven controls without
  short-circuiting, logs every verdict, and aggregates locally (worst status, maximum risk).

## 4. Controls in detail

### SA-001 Source tracking
- **Description:** checks that every retrieved document carries a `doc_id` and a `source`.
- **Risk addressed:** answers that cannot be traced to a document (failure 4).
- **Example attack:** an injected chunk reaches the context without provenance metadata.
- **Tested by:** `test_sa001_flags_doc_without_source`, the audit-log integration test (the source list is
  in the logged evidence), and every payload row (SA-001 must pass on well-formed documents).
- **Outcome:** reliable on its narrow job. Not measured by the evaluation sets, where all documents are
  well-formed. Limitation: it checks that metadata exists, not that it is true.

### SA-002 Response vs retrieved documents
- **Description:** citation markers are removed, the answer is split into sentences, and each sentence is
  compared with the retrieved sentences; a sentence is supported if its best similarity reaches the
  threshold or if at least 80% of its content words appear in its best document.
- **Risk addressed:** unsupported claims (failure 1).
- **Example attack:** "Our headquarters are located in Berlin. We ship by drone on Sundays." from documents
  about refunds and shipping.
- **Tested by:** payload rows, demo scenario "Fabricated facts", evaluation kind `unsupported`.
- **Outcome:** caught 4/4 unsupported answers in the fresh set (all blocked); 1 false alarm on 25
  acceptable answers (a correct paraphrase using "pay nothing" for "not charged").
- **Limitations:** embeddings measure topic, not agreement, so wrong numbers and negations still look
  supported; that is why SA-003 exists.

### SA-003 Hallucination score
- **Description:** `score = 0.6 * unsupported_ratio + 0.4 * (ungrounded numbers or names) + 0.2 * (contradictions)`,
  capped at 1. Numbers and names are checked against the cited documents. Warn from 0.25, block from 0.7.
- **Risk addressed:** wrong numbers and invented names that look supported (failure 2).
- **Example attack:** "You can request a refund within 30 days" when the document says 14.
- **Tested by:** `test_sa003_*` (hand-made SA-002 verdicts), payload rows, evaluation kinds `wrong_number`,
  `negation`, `refusal_with_claim`.
- **Outcome:** 7 of 10 faulty answers of its kinds caught in the fresh set (wrong numbers 4/4, refusal with
  hidden claim 3/3, negation 0/3). 1 false alarm on 25.
- **Limitations:** negation errors are not detected (the price of the low false-alarm rate); a wrong number
  that also appears elsewhere in the same cited document is not caught (documented xfail); numbers written
  as words and names at the start of a sentence are not compared.

### SA-004 Retrieval relevance
- **Description:** best similarity between the question and any retrieved document (question-to-passage
  model); below the threshold the retrieval is flagged. A pure refusal passes, because irrelevant retrieval
  is then the expected situation.
- **Risk addressed:** the wrong documents were retrieved (failure 6): a faithful answer to irrelevant text.
- **Example attack / failure:** a password-reset question answered from the shipping policy.
- **Tested by:** payload rows, demo scenario "Irrelevant retrieval", evaluation kind `irrelevant_retrieval`.
- **Outcome:** caught 4/4 irrelevant retrievals in the fresh set (2/4 in the dev set), but it is the weakest
  control: 3 of the 4 fresh-set false alarms came from it (relevant documents scored 0.331 and 0.333 against
  a threshold of 0.34).
- **Limitations:** model and threshold depend on the document collection and were calibrated on a small
  one; the synthetic "irrelevant" calibration pairs may be partly relevant.

### SA-005 Attribution
- **Description:** the answer must cite documents that were retrieved. Fake citation: block. No citation:
  warn. A pure refusal needs no citation.
- **Risk addressed:** non-attributable or falsely attributed answers (failure 4).
- **Example attack:** "Refunds take 14 days [kb-999]" when kb-999 was never retrieved.
- **Tested by:** `test_sa005_*`, payload rows, evaluation kinds `no_citation` and `fake_citation`.
- **Outcome:** 6/6 caught in the fresh set, 0 false alarms on 25.
- **Limitations:** any bracketed token matching the pattern counts as a citation (for example a numeric
  footnote [1]); it checks that the cited document was retrieved, not that it supports the claim.

### SA-006 Source trust
- **Description:** each source has a trust level in `policy.yaml` (unknown sources default to `low`). The
  verdict follows the least trusted source the answer relies on; untrusted: block, low: warn.
  `evidence["trust_footer"]` holds a ready-made line such as "Sources: refund_policy.pdf (trust: high)".
  A control may not change `ctx`, so appending the footer is the caller's job.
- **Risk addressed:** a faithful answer built on a poisoned or low-trust document (failure 5).
- **Example attack:** a forum post claims "refunds are available for 90 days" and the LLM repeats it.
- **Tested by:** `test_sa006_*`, payload rows, demo scenario "Faithful to a poisoned low-trust source",
  evaluation kind `poisoned_source`.
- **Outcome:** 3/3 caught in the fresh set, 0 false alarms on 25.
- **Limitations:** trust levels are a manual list; a trusted but wrong document is undetectable.

### SA-007 Auto-disable
- **Description:** counts blocked requests per session (sliding window of 5); 3 blocks disable RAG for
  that session (`evidence["rag_disabled"]`, helper `is_rag_disabled`) until `reset_session()`.
- **Risk addressed:** an attacker or a broken retriever repeatedly producing bad answers.
- **Example attack:** three fabricated-answer requests in a row in one session.
- **Tested by:** `test_sa007_*` (latch, session isolation, reset, off-topic warnings not counted) and the
  end-to-end runner test; demo Part 2.
- **Outcome:** works as designed in functional tests. It is session-level, so it is not part of the
  per-answer evaluation.
- **Limitations:** state is in memory only (lost on restart), per process and not thread-safe; the window
  and limit values are heuristic.

## 5. How it was tested

- `py -m pytest domains/domain7_source_attribution_rag/tests/ -v`
- Current result: **66 passed, 3 xfailed.** The xfails are documented limitations: the orchestrator does
  not fill `prior_verdicts` (needs a team decision on `core/`), the negation row (a lone conflict stays
  below the warn threshold), and the wrong number that also appears in the same cited document.
- Files: `tests/payloads.csv` (benign / malicious / known_gap rows), unit tests with hand-made verdicts,
  orchestrator and audit-log integration tests, runner tests, integrity tests for both labelled sets.
- The shared `tests/integration/` suite passes unchanged (Domain 7 is not registered there yet).

## 6. Measured evaluation

**Method.** Two labelled sets of answers, scored with SA-001 to SA-006 (SA-007 is session-level):
- **Dev set** (`eval_set.py`): 60 examples (28 acceptable, 32 faulty) on a library knowledge base. It was
  used to find problems and to calibrate two thresholds, so its numbers are optimistic.
- **Fresh test set** (`eval_set_test.py`): 52 examples (25 acceptable, 27 faulty) on a bike-share knowledge
  base written after the fixes and the calibration. No threshold was changed because of it.
- Two decision rules: "warn or block" flags any answer a control warns about or blocks; "block only" flags
  only blocked answers.
- Reproduce: `py domains\domain7_source_attribution_rag\evaluate_domain7.py --set test` (or `--set dev`).

**Fresh test set results**

| decision rule | TP | FP | TN | FN | accuracy | precision | recall | false-positive rate |
|---|---|---|---|---|---|---|---|---|
| warn or block | 24 | 4 | 21 | 3 | 87% | 86% | 89% | 16% |
| block only | 13 | 1 | 24 | 14 | 71% | 93% | 48% | 4% |

With 52 examples the uncertainty is large (approximate 95% intervals: recall 72-96%, false-positive
rate 6-35%, accuracy 75-93%).

| kind (fresh set) | flagged | expected control flagged |
|---|---|---|
| unsupported | 4/4 (all blocked) | SA-002 4/4 |
| wrong_number | 4/4 | SA-003 4/4 |
| negation | 0/3 | SA-003 0/3 |
| no_citation | 3/3 | SA-005 3/3 |
| fake_citation | 3/3 (all blocked) | SA-005 3/3 |
| poisoned_source | 3/3 (all blocked) | SA-006 3/3 |
| irrelevant_retrieval | 4/4 | SA-004 4/4 |
| refusal_with_claim | 3/3 (all blocked) | SA-003 3/3 |
| acceptable answers flagged | 4/25 (SA-004: 3, SA-002/003: 1) | |

**Progress.** Dev set baseline before the fixes: accuracy 78%, recall 78%, false-positive rate 21%.
After the fixes, the calibration and option A: accuracy 90%, recall 88%, false-positive rate 7%.
The fresh set shows the honest picture: similar recall (89%) but a higher false-positive rate (16%).

**Latency.** The six per-answer controls take a median of 55 ms per answer on a laptop CPU (mean 67 ms,
p95 164 ms) on the fresh set; the same code measured on the dev set in a separate run gave a median of
162 ms, so latency varies about 2-3 times between runs on this machine. Almost all of the time is the two
embedding controls (SA-002 and SA-004); SA-001, 003, 005 and 006 take under 1 ms each.

**Honest limits of this evaluation**
- Small sets (60 and 52 examples) and one author for the controls and for both sets; the author knew the
  controls' weak spots. A reviewer should add examples of their own.
- All answers were written by hand. Answers produced by a real LLM fail in different and messier ways.
- One small knowledge base per set; SA-004 in particular depends on the collection.
- SA-007 and SA-001 are covered by functional tests, not by these sets.

## 7. Known limitations and open integration questions

- Negation errors are mostly not detected; SA-004 is the weakest control; a faithful answer from a trusted
  but wrong source cannot be detected by any Domain 7 control.
- `core/orchestrator.py` never fills `ctx.metadata["prior_verdicts"]`, which SA-003, SA-007 and Domain 2's
  RC-006 depend on. Proposal for the team: append each verdict in `run_layer`.
- Plain chat (no RAG) would trigger Domain 7 warnings (an answer with no retrieved documents and no
  citation). A convention such as `ctx.metadata["domain7_rag_used"]` is needed before registering Domain 7
  in the shared pipeline.
- Registering Domain 7 in the shared integration test needs the team's agreement (5 domains, 14 egress
  controls instead of 7).

## 8. Running it

    py domains\domain7_source_attribution_rag\demo_domain7.py
    py -m streamlit run dashboard/streamlit_app.py --server.fileWatcherType none
    py -m pytest domains/domain7_source_attribution_rag/tests/ -q
    py domains\domain7_source_attribution_rag\calibrate_domain7.py          (report only; --apply writes policy.yaml)


Files: `controls/`, `common.py`, `config/policy.yaml`, `demo_data.py`, `demo_domain7.py`,
`dashboard_section.py`, `eval_set.py`, `eval_set_test.py`, `evaluate_domain7.py`, `calibrate_domain7.py`,
`evaluation_report*.md`, `calibration_report.txt`, `tests/`.

Manual check: the demo was tried by hand with the sample documents (normal answer, each tamper mode, an untrusted source, a question the document cannot answer, and repeated blocked requests) and behaved as designed. This is a manual check, not a measurement.


## 10. Shared pipeline integration

The open questions in section 7 were resolved in the shared files (backwards compatible):

- `core/orchestrator.py` sets `ctx.metadata["prior_verdicts"]` before every control (verdicts of the
  controls that already ran in the same layer), so SA-003, SA-007 and Domain 2's RC-006 now work through
  the orchestrator.
- `core/control_base.py` has `always_run = False`. After a block the orchestrator skips the remaining
  controls of the layer except those with `always_run = True`. SA-007 sets it so that it still counts
  blocked requests.
- `ctx.metadata["domain7_rag_used"] = False` marks a request as plain chat: all seven controls pass with
  "RAG not used". If the key is absent, behaviour is unchanged.
- Domain 7 is registered in `tests/integration/test_end_to_end.py` (5 domains, 14 egress controls),
  `demo/demo_agent.py` and `config/global_policy.yaml`. `pypdf` is in `requirements.txt` for PDF uploads.