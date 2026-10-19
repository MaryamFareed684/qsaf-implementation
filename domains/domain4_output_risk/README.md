# Domain 4: Output Risk & Response Control

**Layer:** `egress`
**Owner:** QSAF team
**Status:** Phase 1 — implemented offline rule-based controls

## What this domain protects against
Domain 4 checks the agent's reply after generation and before it reaches a user
or downstream system. It identifies unsafe or illegal response content,
possible unsupported claims, sensitive-data leakage, off-topic replies, and
unexpected tone changes. It does not inspect agent internals and does not
replace Domain 10's blank-output check.

The failure source is the agent's own output. All controls operate at the
`egress` layer and read only `RequestContext`; retrieved documents,
conversation history, and tool calls are optional supporting context.

The QSAF Control Book provides one-line descriptions for OR-001 through
OR-007. Detection patterns, weights, thresholds, and fallback behavior in
this implementation are team design decisions stored in
`config/policy.yaml`.

## Controls in this domain

| Control ID | File | Description |
|---|---|---|
| OR-001 | `or_001_jailbreak_output_filter.py` | Jailbroken-Content Output Filter |
| OR-002 | `or_002_hallucination_flag.py` | Hallucinated-Fact Flagging |
| OR-003 | `or_003_output_watermark.py` | Output Token Watermarking |
| OR-004 | `or_004_sensitivity_scoring.py` | Response Sensitivity Scoring |
| OR-005 | `or_005_risky_reroute.py` | Risky Content Block/Reroute |
| OR-006 | `or_006_prompt_response_correlation.py` | Prompt-Response Correlation Check |
| OR-007 | `or_007_tone_deviation.py` | Tone / Sentiment Deviation Monitor |

## Control designs and outcomes

### OR-001 — Jailbroken-content output filter

Normalizes the reply to reduce simple obfuscation, applies policy-configured
jailbreak and dangerous-content patterns, combines matches with a noisy-OR
score, and discounts clear refusals or news-style reporting. High-risk
self-harm and minors-sexual categories escalate; other high-risk replies
block. Evidence contains rule IDs and counts, never the reply text.

**Example scenario:** a reply claims “DAN mode enabled” or offers placeholder
step-style harmful instructions. **Tested with:** benign technical/educational
replies, refusals, obfuscation, news context, and safe placeholders.
**Limit:** pattern matching cannot understand every paraphrase or context.

### OR-002 — Hallucinated-fact flagging

Uses weak signals such as unsourced URLs/emails, precise statistics, vague
authority claims, and citation-shaped text. When retrieved documents exist, it
also checks checkable claims for lexical support. It only returns `pass` or
`warn`, with a configured risk cap; it never claims that a hallucination is
proven.

**Example scenario:** a reply invents a source URL and an exact statistic.
**Tested with:** clean replies, source-supported claims, unsupported claims,
and prompt-sourced URLs. **Limit:** truth cannot be established without
authoritative ground truth; lexical grounding can miss paraphrases.

### OR-003 — Output fingerprint watermark

Creates a response fingerprint from the session ID and reply. When
`QSAF_WATERMARK_KEY` is configured it uses HMAC-SHA256; otherwise it uses an
explicitly labelled unkeyed SHA-256 fallback. The fingerprint is recorded in
verdict evidence without changing the reply.

**Example scenario:** an audit reviewer recomputes a fingerprint to check
whether a reply was altered. **Tested with:** repeatability, changed inputs,
keyed/unkeyed modes, and tamper detection. **Limit:** this is traceability
fingerprinting, not model-internal token watermarking.

### OR-004 — Response sensitivity scoring

Detects configured email, phone, card, national-ID, bank-account, credential,
API-key, and private-key patterns. Card-like numbers use Luhn validation.
Category scores combine into pass/warn/block thresholds. Evidence and reasons
contain masked samples only.

**Example scenario:** a reply includes a fake email and test card number.
**Tested with:** fake sensitive values, invalid card numbers, benign password
mentions, masking, and threshold changes. **Limit:** regex detection can miss
unusual formats and can still require tuning for domain-specific identifiers.

### OR-005 — Risky-content block/reroute action

Runs the other Domain 4 detectors it depends on, combines their weighted
scores, and selects allow, allow-with-warning, reroute, block, or escalation.
Because `Verdict` has no reroute status, reroute is represented as `block` with
`evidence["action"] == "reroute"` and a policy-configured fallback message.

**Example scenario:** a detected data leak is replaced with a safe fallback,
while self-harm content is escalated to a moderator. **Tested with:** benign,
jailbreak, data-leak, moderate-risk, and escalation cases. **Limit:** it
re-evaluates detectors for order independence and therefore has duplicated
work; a future shared-result mechanism could remove that cost.

### OR-006 — Prompt-response correlation

Compares important prompt words with reply words using configured stopwords
and simple stemming. Very short prompts, short replies, and deliberate
refusals are skipped. Low lexical coverage produces a capped warning.

**Example scenario:** a question about baking receives unrelated stock-market
advice. **Tested with:** on-topic answers, off-topic answers, refusals, short
inputs, and word-form variations. **Limit:** lexical overlap can under-score
correct answers that use different vocabulary.

### OR-007 — Tone and sentiment deviation

Uses policy-configured positive and negative lexicons, hostile/manipulative
patterns, shouting indicators, and earlier assistant messages in
`conversation_history`. Sudden sentiment shifts and strong wording produce
warnings or blocks according to policy.

**Example scenario:** a normally helpful assistant suddenly becomes insulting
and coercive. **Tested with:** neutral replies, hostile/manipulative language,
shouting, threats, and historical sentiment shifts. **Limit:** the first
version is English-only and lexicon-based, so nuanced tone may be missed.

## How to run this domain's demo standalone

```bash
python domains/domain4_output_risk/demo_domain4.py
pytest domains/domain4_output_risk/tests/ -v
```

The shared dashboard imports `render_domain4_tab()` from
`dashboard_section.py`. It provides prompt/reply text boxes, benign and
placeholder attack examples, and one result panel per control.

## Configuration and privacy

All thresholds, weights, patterns, stopwords, and fallback text are in
`config/policy.yaml`; no detector threshold is hardcoded in a control. The
controls never put full replies, harmful examples, or detected secrets into
verdict evidence. Sensitive matches are masked before the shared audit logger
records them.
