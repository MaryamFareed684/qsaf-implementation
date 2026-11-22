"""Measures the cheap Domain 1 controls and PI-003 on the DEV set. Read-only: changes no policy."""
from core.models import RequestContext
from domains.domain1_prompt_injection.controls.pi_008_token_sanitizer import TokenSanitizerPI008
from domains.domain1_prompt_injection.controls.pi_001_blacklist import BlacklistPI001
from domains.domain1_prompt_injection.controls.pi_007_token_anomaly import TokenAnomalyPI007
from domains.domain1_prompt_injection.controls.pi_003_embedding_similarity import EmbeddingSimilarityPI003
from domains.domain1_prompt_injection.eval_set_d1 import DEV_SET


def run():
    san, c1, c7, c3 = TokenSanitizerPI008(), BlacklistPI001(), TokenAnomalyPI007(), EmbeddingSimilarityPI003()
    rows = []
    for label, kind, text in DEV_SET:
        ctx = RequestContext(session_id="eval", user_id="eval", raw_prompt=text)
        ctx.metadata["cleaned_prompt"] = san.evaluate(ctx).evidence["cleaned_prompt"]
        v = {"PI-001": c1.evaluate(ctx), "PI-007": c7.evaluate(ctx), "PI-003": c3.evaluate(ctx)}
        rows.append((label, kind, text, v))
    return rows


def rate(rows, flagged):
    atk = [r for r in rows if r[0] == "attack"]
    ben = [r for r in rows if r[0] == "benign"]
    tp = sum(1 for r in atk if flagged(r))
    fp = sum(1 for r in ben if flagged(r))
    return tp, len(atk), fp, len(ben)


def main():
    rows = run()
    print("Per control (flagged = status is not pass), policy settings as they are now:")
    for cid in ("PI-001", "PI-007", "PI-003"):
        tp, na, fp, nb = rate(rows, lambda r, c=cid: r[3][c].status != "pass")
        print("  %s  attacks caught %d/%d   benign flagged %d/%d" % (cid, tp, na, fp, nb))
    tp, na, fp, nb = rate(rows, lambda r: any(x.status != "pass" for x in r[3].values()))
    print("  ANY of the three  attacks caught %d/%d   benign flagged %d/%d" % (tp, na, fp, nb))
    print("\nWrong answers of ANY (score is the PI-003 similarity):")
    for label, kind, text, v in rows:
        flagged = any(x.status != "pass" for x in v.values())
        if (label == "attack" and not flagged) or (label == "benign" and flagged):
            who = ",".join(k for k, x in v.items() if x.status != "pass") or "none"
            print("  %-6s %-13s flagged_by=%-12s pi003=%.3f  %s" % (label, kind, who, v["PI-003"].evidence["similarity_score"], text[:60]))
    print("\nPI-003 alone, threshold sweep (flag when score > t):")
    for i in range(6, 19):
        t = i * 0.05
        tp, na, fp, nb = rate(rows, lambda r, t=t: r[3]["PI-003"].evidence["similarity_score"] > t)
        print("  t=%.2f  attacks caught %2d/%d   benign flagged %2d/%d" % (t, tp, na, fp, nb))
    print("\nPI-003 score by kind (min / max):")
    kinds = {}
    for label, kind, text, v in rows:
        kinds.setdefault((label, kind), []).append(v["PI-003"].evidence["similarity_score"])
    for (label, kind), s in sorted(kinds.items()):
        print("  %-6s %-13s %.3f / %.3f" % (label, kind, min(s), max(s)))


if __name__ == "__main__":
    main()