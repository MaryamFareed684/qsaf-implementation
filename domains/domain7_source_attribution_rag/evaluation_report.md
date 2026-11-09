# Domain 7 evaluation

Set: DEV set (thresholds were calibrated on it)

Examples: 60 (28 acceptable, 32 faulty). Controls SA-001 to SA-006; SA-007 is session-level and covered by functional tests.

## Overall

| decision rule | TP | FP | TN | FN | accuracy | precision | recall | false-positive rate |
|---|---|---|---|---|---|---|---|---|
| warn or block | 28 | 2 | 26 | 4 | 90% | 93% | 88% | 7% |
| block only | 18 | 1 | 27 | 14 | 75% | 95% | 56% | 4% |

## By example kind

| kind | label | n | flagged (warn or block) | flagged (block) | expected control flagged |
|---|---|---|---|---|---|
| benign_direct | ok | 6 | 0/6 | 0/6 |  |
| benign_paraphrase | ok | 12 | 1/12 | 0/12 |  |
| benign_multi | ok | 4 | 0/4 | 0/4 |  |
| benign_refusal | ok | 2 | 0/2 | 0/2 |  |
| benign_short | ok | 4 | 1/4 | 1/4 |  |
| unsupported | bad | 6 | 6/6 | 6/6 | 6/6 |
| wrong_number | bad | 6 | 6/6 | 1/6 | 6/6 |
| negation | bad | 4 | 2/4 | 2/4 | 2/4 |
| no_citation | bad | 4 | 4/4 | 1/4 | 4/4 |
| fake_citation | bad | 4 | 4/4 | 4/4 | 4/4 |
| poisoned_source | bad | 4 | 4/4 | 4/4 | 4/4 |
| irrelevant_retrieval | bad | 4 | 2/4 | 0/4 | 2/4 |

## By control (latency in milliseconds, 3 passes after warm-up)

| control | false alarms on acceptable answers | caught its own failure kind | mean ms | median ms | p95 ms |
|---|---|---|---|---|---|
| SA-001 | 0/28 | - | 0.0 | 0.0 | 0.0 |
| SA-002 | 1/28 | 6/6 | 91.2 | 92.6 | 105.6 |
| SA-003 | 1/28 | 8/10 | 0.3 | 0.3 | 0.5 |
| SA-004 | 1/28 | 2/4 | 68.7 | 66.9 | 79.9 |
| SA-005 | 0/28 | 8/8 | 0.1 | 0.0 | 0.1 |
| SA-006 | 0/28 | 4/4 | 0.1 | 0.1 | 0.1 |
| pipeline | - | - | 160.3 | 162.4 | 183.5 |

## Missed faulty answers (false negatives, warn or block rule)

- E42 [negation] Is membership free for students from other districts? -> Students from other districts can join for free [ev-002].
- E43 [negation] Is the library open on Sundays? -> The library is open on Sundays [ev-003].
- E58 [irrelevant_retrieval] Does the library lend telescopes? -> Study rooms can be booked for up to 3 hours per day [ev-004].
- E60 [irrelevant_retrieval] How do I apply for a job at the library? -> Scanning is free [ev-006].

## Acceptable answers that were flagged (false positives)

- E11 [benign_paraphrase] Do I need a card? -> SA-004: No retrieved document is relevant to the question (best similarity 0.307).
- E25 [benign_short] How long is the loan period? -> SA-002: 1 of 1 answer sentence(s) are not supported by the retrieved documents.; SA-003: Possible hallucination (0.6). Details: 100% of answer sentences unsupported.
