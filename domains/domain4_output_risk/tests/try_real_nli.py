"""
Run this ONCE on your own machine to try the REAL NLI model used by OR-002.
(The unit tests use a fake model, so they cannot tell you how the real one behaves.)

    python domains/domain4_output_risk/tests/try_real_nli.py

Needs: sentence-transformers installed, and internet the first time (the model is downloaded).
It prints what the model thinks of three example claims, then runs OR-002 end to end
with grounding.method set to "nli" (only in memory; policy.yaml is not changed).
"""

import copy
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from core.models import RequestContext  # noqa: E402
from core.policy_loader import load_domain_policy  # noqa: E402
from domains.domain4_output_risk.controls import or_002_hallucination_flag as m002  # noqa: E402

DOC = "The Karakoram Highway was completed in 1979 and links Pakistan with China."
CLAIMS = {
    "SUPPORTED   ": "The Karakoram Highway was completed in 1979.",
    "CONTRADICTED": "The Karakoram Highway was completed in 1985.",
    "NOT COVERED ": "The Karakoram Highway has exactly 4 tunnels.",
}

cfg = load_domain_policy("domain4_output_risk")["or_002_hallucination"]
nli = cfg["grounding"]["nli"]
labels = [str(x).lower() for x in nli["label_order"]]

print(f"Loading model {nli['model_name']} (first run downloads it)...")
verify = m002._build_default_verifier(nli["model_name"], labels)

model = m002._NLI_MODELS.get(nli["model_name"])
id2label = getattr(getattr(model, "config", None), "id2label", None)
print("Label order in policy.yaml :", labels)
print("Label order in model config:", id2label if id2label else "(not available, check the model card)")
print("If these two disagree, fix nli.label_order in policy.yaml.\n")

for name, claim in CLAIMS.items():
    probs = verify([(DOC, claim)])[0]
    shown = "  ".join(f"{k}={v:.2f}" for k, v in probs.items())
    print(f"{name} | {shown}")

print("\nExpected: SUPPORTED has high entailment, CONTRADICTED has high contradiction.")

# End to end through the control, with method switched to nli in memory only.
cfg2 = copy.deepcopy(load_domain_policy("domain4_output_risk"))
cfg2["or_002_hallucination"]["grounding"]["method"] = "nli"
control = m002.HallucinationFlagOR002()
ctx = RequestContext(session_id="try", user_id="u", raw_prompt="Tell me about the highway",
                     agent_output="The Karakoram Highway was completed in 1985 and links Pakistan with India.",
                     retrieved_docs=[{"content": DOC}])
with patch.object(m002, "load_domain_policy", return_value=cfg2):
    v = control.safe_evaluate(ctx)
print("\nOR-002 verdict:", v.status.upper(), f"risk={v.risk_score:.2f}")
print("Reason        :", v.reason)
print("Method used   :", v.evidence["grounding_method_used"], "| fallback:", v.evidence.get("nli_fallback", False))
