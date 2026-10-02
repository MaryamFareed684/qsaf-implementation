from core.control_base import Control
from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy
from collections import Counter
import math


def calculate_entropy(text: str) -> float:
    """Shannon entropy: higher = more random-looking, lower = more predictable (normal English)."""
    if not text:
        return 0.0

    char_counts = Counter(text)
    total_chars = len(text)

    entropy = 0.0
    for count in char_counts.values():
        probability = count / total_chars
        entropy += -probability * math.log2(probability)

    return entropy


def detect_repetition(text: str) -> tuple[bool, str, float]:
    """Checks if any single word makes up an unusually large fraction of the prompt."""
    words = text.lower().split()
    if not words:
        return False, "", 0.0

    word_counts = Counter(words)
    most_common_word, count = word_counts.most_common(1)[0]
    fraction = count / len(words)

    return fraction > 0.3, most_common_word, fraction  # 30% threshold


class TokenAnomalyPI007(Control):
    control_id = "PI-007"
    domain = "Domain 1: Prompt Injection Protection"
    layer = "ingress"

    def evaluate(self, ctx: RequestContext) -> Verdict:
        policy = load_domain_policy("domain1_prompt_injection")
        config = policy.get("token_anomaly", {})
        max_length = config.get("max_length", 2000)
        entropy_threshold = config.get("entropy_threshold", 4.5)

        prompt_to_check = ctx.metadata.get("cleaned_prompt", ctx.raw_prompt)

        issues = []

        # Check 1: length
        if len(prompt_to_check) > max_length:
            issues.append(f"Prompt length ({len(prompt_to_check)}) exceeds max ({max_length}).")

        # Check 2: repetition
        is_repetitive, repeated_word, fraction = detect_repetition(prompt_to_check)
        if is_repetitive:
            issues.append(f"Word '{repeated_word}' makes up {fraction:.0%} of the prompt.")

        # Check 3: entropy
        entropy_score = calculate_entropy(prompt_to_check)
        if entropy_score > entropy_threshold:
            issues.append(f"High entropy ({entropy_score:.2f}) suggests encoded/random content.")

        if issues:
            return Verdict(
                control_id=self.control_id,
                domain=self.domain,
                status="warn",
                risk_score=0.5,
                reason=f"Token anomaly detected: {'; '.join(issues)}",
                evidence={"issues": issues, "entropy": entropy_score},
            )

        return Verdict(
            control_id=self.control_id,
            domain=self.domain,
            status="pass",
            risk_score=0.0,
            reason="No token anomalies detected.",
            evidence={"entropy": entropy_score},
        )


if __name__ == "__main__":
    control = TokenAnomalyPI007()

    # Test 1: normal prompt
    ctx1 = RequestContext(session_id="t1", user_id="maryam",
                           raw_prompt="Summarize this document for me.")
    v1 = control.evaluate(ctx1)
    print("--- Normal prompt ---")
    print("Status:", v1.status, "| Entropy:", v1.evidence["entropy"])

    # Test 2: base64-like encoded text (high entropy)
    ctx2 = RequestContext(session_id="t2", user_id="maryam",
                           raw_prompt="aGVsbG8gd29ybGQgdGhpcyBpcyBiYXNlNjQgZW5jb2RlZCB0ZXh0IGZvciB0ZXN0aW5n")
    v2 = control.evaluate(ctx2)
    print("--- Base64-like prompt ---")
    print("Status:", v2.status, "| Entropy:", v2.evidence["entropy"])

    # Test 3: repetitive prompt
    ctx3 = RequestContext(session_id="t3", user_id="maryam",
                           raw_prompt="continue continue continue continue continue continue continue")
    v3 = control.evaluate(ctx3)
    print("--- Repetitive prompt ---")
    print("Status:", v3.status, "| Reason:", v3.reason)