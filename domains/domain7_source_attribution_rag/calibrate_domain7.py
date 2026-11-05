r"""
Calibrate the two embedding thresholds of Domain 7 on the labelled DEV set (eval_set.py).

  py domains\domain7_source_attribution_rag\calibrate_domain7.py            (report only)
  py domains\domain7_source_attribution_rag\calibrate_domain7.py --apply    (also writes policy.yaml)

SA-002: support_threshold  = best separation between sentences of acceptable answers and
        sentences of 'unsupported' answers (the lexical fallback is kept as configured).
SA-004: model_name + relevance_threshold = best separation between questions with relevant
        documents and questions with irrelevant ones, for each candidate model. The
        irrelevant cases are the hand-written 'irrelevant_retrieval' rows plus synthetic ones
        (each question paired with the documents of a different row). Some synthetic pairs may
        in fact be partly relevant, so treat the numbers as approximate.
The threshold is the middle of the range that maximises balanced accuracy.
Never report final numbers on the data used here: use the fresh test set.
"""

import argparse
import re
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.models import RequestContext
from domains.domain7_source_attribution_rag import common
from domains.domain7_source_attribution_rag.controls.sa_002_response_vs_docs import ResponseVsDocsSA002, _get_model
from domains.domain7_source_attribution_rag.eval_set import EVAL_KB, EXAMPLES

POLICY_FILE = HERE / "config" / "policy.yaml"
CANDIDATE_MODELS = ["all-MiniLM-L6-v2", "multi-qa-MiniLM-L6-cos-v1"]


def ctx_for(question, doc_ids, answer=""):
    return RequestContext(session_id="calibrate", user_id="cal", raw_prompt=question,
                          retrieved_docs=[dict(EVAL_KB[i]) for i in doc_ids], agent_output=answer)


def choose(cands, score_fn):
    scored = [(score_fn(t), t) for t in cands]
    best = max(s for s, _ in scored)
    ties = sorted(t for s, t in scored if abs(s - best) < 1e-9)
    return ties[len(ties) // 2], best


def candidates(values):
    v = sorted(set(values))
    return [v[0] - 0.01] + [(a + b) / 2 for a, b in zip(v, v[1:])] + [v[-1] + 0.01]


def set_value(text, section, key, new_line):
    out, current, done = [], None, False
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z_]+):\s*$", line)
        if m:
            current = m.group(1)
        if current == section and re.match(rf"^  {key}:", line):
            line, done = new_line, True
        out.append(line)
    if not done:
        raise SystemExit(f"{section}.{key} not found in policy.yaml")
    return "\n".join(out) + "\n"


def calibrate_sa002():
    control = ResponseVsDocsSA002()
    lex = float(common.load_policy()["response_vs_docs"]["lexical_support"])
    pos, neg = [], []
    for ex in EXAMPLES:
        if ex["kind"] == "benign_refusal" or ex["kind"] not in ("unsupported",) and not ex["kind"].startswith("benign"):
            continue
        v = control.evaluate(ctx_for(ex["question"], ex["doc_ids"], ex["answer"]))
        recs = [(r["max_similarity"], r["lexical_coverage"]) for r in v.evidence.get("sentences", [])]
        (neg if ex["kind"] == "unsupported" else pos).extend(recs)

    def balanced(t):
        tpr = np.mean([(s >= t or c >= lex) for s, c in pos])
        tnr = np.mean([not (s >= t or c >= lex) for s, c in neg])
        return (tpr + tnr) / 2

    t, bal = choose(candidates([s for s, _ in pos + neg]), balanced)
    print(f"SA-002 support_threshold: {t:.3f}  (balanced accuracy {bal:.2f} on {len(pos)} supported and {len(neg)} unsupported sentences)")
    print(f"   supported sentences:   min sim {min(s for s, _ in pos):.3f}")
    print(f"   unsupported sentences: max sim {max(s for s, _ in neg):.3f}")
    return round(t, 3)


def calibrate_sa004():
    ok_rows = [e for e in EXAMPLES if e["label"] == "ok" and e["kind"] != "benign_refusal"]
    neg_cases = [(e["question"], e["doc_ids"]) for e in EXAMPLES if e["kind"] == "irrelevant_retrieval"]
    for i, e in enumerate(ok_rows):
        for off in range(1, len(ok_rows)):
            other = ok_rows[(i + off) % len(ok_rows)]
            if set(other["doc_ids"]).isdisjoint(e["doc_ids"]):
                neg_cases.append((e["question"], other["doc_ids"]))
                break
    pos_cases = [(e["question"], e["doc_ids"]) for e in ok_rows]

    results = []
    for name in CANDIDATE_MODELS:
        model = _get_model(name)
        cache = {}

        def best_sim(question, doc_ids):
            texts = [question] + [EVAL_KB[i]["text"] for i in doc_ids]
            key = tuple(texts)
            if key not in cache:
                emb = model.encode(texts, normalize_embeddings=True)
                cache[key] = float(np.max(emb[1:] @ emb[0]))
            return cache[key]

        pos = [best_sim(q, d) for q, d in pos_cases]
        neg = [best_sim(q, d) for q, d in neg_cases]
        t, bal = choose(candidates(pos + neg),
                        lambda t: (np.mean([p >= t for p in pos]) + np.mean([n < t for n in neg])) / 2)
        results.append({"model": name, "threshold": round(t, 3), "bal": bal,
                        "pos_min": min(pos), "pos_mean": float(np.mean(pos)),
                        "neg_max": max(neg), "neg_mean": float(np.mean(neg))})
        print(f"SA-004 {name}: threshold {t:.3f}, balanced accuracy {bal:.2f} "
              f"(relevant: min {min(pos):.3f} mean {np.mean(pos):.3f}; "
              f"irrelevant: max {max(neg):.3f} mean {np.mean(neg):.3f}; "
              f"{len(pos)} relevant and {len(neg)} irrelevant cases)")
    return max(results, key=lambda r: r["bal"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="write the chosen values into policy.yaml")
    args = parser.parse_args()

    t002 = calibrate_sa002()
    best = calibrate_sa004()
    print(f"\nChosen for SA-004: {best['model']} with threshold {best['threshold']} (balanced accuracy {best['bal']:.2f})")

    if args.apply:
        text = POLICY_FILE.read_text(encoding="utf-8")
        text = set_value(text, "response_vs_docs", "support_threshold",
                         f"  support_threshold: {t002}     # calibrated on the dev set")
        text = set_value(text, "retrieval_relevance", "model_name",
                         f'  model_name: "{best["model"]}"   # chosen on the dev set')
        text = set_value(text, "retrieval_relevance", "relevance_threshold",
                         f"  relevance_threshold: {best['threshold']}        # calibrated on the dev set")
        POLICY_FILE.write_text(text, encoding="utf-8")
        print("policy.yaml updated.")
    else:
        print("policy.yaml NOT changed (use --apply to write these values).")


if __name__ == "__main__":
    main()