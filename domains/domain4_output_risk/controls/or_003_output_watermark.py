"""
domains/domain4_output_risk/controls/or_003_output_watermark.py

QSAF-OR-003: Token-based watermarking for response traceability (auditable, egress).

TWO layers:

  1) FINGERPRINT (always on). HMAC-SHA256( secret key , session_id + reply ) goes into the
     Verdict evidence and so into the audit log. Anyone holding the key can later recompute it
     (see verify_fingerprint). IMPORTANT LIMIT: this proves our system RECORDED this exact text
     for this session. It does NOT prove an AI wrote the text, and any edit changes it.

  2) TOKEN WATERMARK DETECTION (optional, off by default). Works only when the model is
     self-hosted AND its generation step nudges token choices using bias_logits() below AND the
     pipeline passes the generated token ids in ctx.metadata["domain4_token_ids"].
     Idea (the "green list" method): for every token, a secret key and the previous token decide
     whether the token is "green". A watermarked model prefers green tokens, so its text has far
     more green tokens than chance. detect_token_watermark() measures this with a z-score.
     A detection says "this text was very probably generated with our key" (statistical evidence,
     not proof). No detection proves nothing: the text may have been edited or paraphrased.

Both keys come from ENVIRONMENT VARIABLES named in policy.yaml, never from the source code.
Wiring bias_logits() into a real model's generation loop is the model owner's job (it needs the
model's logits); this file provides the tested pure functions for both sides.
"""

import hashlib
import hmac
import math
import os

from core.control_base import Control
from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy

POLICY_FOLDER = "domain4_output_risk"
POLICY_KEY = "or_003_watermark"


# ----------------------------------------------------------------- 1) fingerprint
def compute_fingerprint(session_id: str, reply: str, key: str = None, length: int = 32) -> tuple:
    """Return (fingerprint_hex, mode). Pure function, so it is easy to test and reuse."""
    message = f"{session_id}\n{reply}".encode("utf-8")
    if key:
        digest = hmac.new(key.encode("utf-8"), message, hashlib.sha256).hexdigest()
        return digest[:length], "hmac-sha256"
    return hashlib.sha256(message).hexdigest()[:length], "sha256-unkeyed"


def verify_fingerprint(session_id: str, reply: str, fingerprint: str, key: str = None, length: int = 32) -> bool:
    """Audit helper: was this reply (in this session) fingerprinted by us?"""
    expected, _ = compute_fingerprint(session_id, reply, key, length)
    return hmac.compare_digest(expected, str(fingerprint))


# ------------------------------------------------------- 2) token watermark (optional)
def is_green(key: str, previous_token: int, token: int, gamma: float) -> bool:
    """Is `token` on the secret 'green list' after `previous_token`? About gamma of all tokens are."""
    digest = hmac.new(key.encode("utf-8"), f"{previous_token}:{token}".encode("utf-8"), hashlib.sha256).digest()
    return int.from_bytes(digest[:8], "big") / 2 ** 64 < gamma


def bias_logits(logits: list, previous_token: int, key: str, gamma: float, delta: float) -> list:
    """
    GENERATION side (for self-hosted models): add `delta` to the score of every green token.
    Call this on the model's raw scores before sampling the next token.
    """
    return [v + delta if is_green(key, previous_token, i, gamma) else v for i, v in enumerate(logits)]


def detect_token_watermark(token_ids: list, key: str, gamma: float, z_threshold: float, min_tokens: int) -> dict:
    """DETECTION side: count green tokens and turn the count into a z-score."""
    n = len(token_ids) - 1                      # number of (previous, current) pairs
    if n < min_tokens:
        return {"tokens_checked": max(n, 0), "green_fraction": None, "z_score": None, "detected": False, "note": "too_short"}
    green = sum(1 for i in range(1, len(token_ids)) if is_green(key, token_ids[i - 1], token_ids[i], gamma))
    z = (green - gamma * n) / math.sqrt(n * gamma * (1.0 - gamma))
    return {"tokens_checked": n, "green_fraction": round(green / n, 3), "z_score": round(z, 2),
            "detected": z >= z_threshold, "note": "ok"}


class OutputWatermarkOR003(Control):
    control_id = "OR-003"
    domain = "Domain 4: Output Risk & Response Control"
    layer = "egress"

    def evaluate(self, ctx: RequestContext) -> Verdict:
        cfg = load_domain_policy(POLICY_FOLDER).get(POLICY_KEY)
        if not cfg:
            return self._verdict("warn", 0.5, f"OR-003 policy section '{POLICY_KEY}' is missing from policy.yaml; no fingerprint created.", {})
        if not cfg.get("enabled", True):
            return self._verdict("pass", 0.0, "OR-003 is disabled in policy.yaml.", {})

        try:
            env_name = str(cfg["key_env_var"])
            key_id = str(cfg.get("key_id", "v1"))
            length = int(cfg["fingerprint_length"])
            on_missing = str(cfg.get("on_missing_key", "unkeyed"))
        except (KeyError, TypeError, ValueError) as exc:
            return self._verdict("warn", 0.5, f"OR-003 policy values are invalid ({type(exc).__name__}); no fingerprint created.", {})

        reply = ctx.agent_output
        if reply is None or not str(reply).strip():
            return self._verdict("pass", 0.0, "No agent output to fingerprint.", {})

        key = os.environ.get(env_name)
        if not key and on_missing == "warn":
            return self._verdict("warn", 0.3, f"Secret key variable {env_name} is not set; no signed fingerprint created.", {"key_env_var": env_name})

        fingerprint, mode = compute_fingerprint(ctx.session_id, str(reply), key, length)
        evidence = {"fingerprint": fingerprint, "mode": mode, "key_id": key_id if key else None, "reply_length": len(str(reply))}
        note = "" if key else f" Set {env_name} for a signed (tamper-proof) fingerprint."
        reason = f"Response fingerprint {fingerprint[:12]}... recorded for traceability ({mode}).{note}"

        # --- optional token watermark detection
        token_cfg = cfg.get("token_watermark", {}) or {}
        if token_cfg.get("enabled", False):
            info = self._token_watermark(ctx, token_cfg)
            evidence["token_watermark"] = info
            if info.get("detected"):
                reason += f" Token watermark detected (z-score {info['z_score']})."
            else:
                reason += f" Token watermark: {info.get('status', 'not detected')}."
        return self._verdict("pass", 0.0, reason, evidence)

    # ----------------------------------------------------------------- helpers
    @staticmethod
    def _token_watermark(ctx: RequestContext, token_cfg: dict) -> dict:
        try:
            gamma = float(token_cfg["gamma"])
            z_threshold = float(token_cfg["z_threshold"])
            min_tokens = int(token_cfg["min_tokens"])
            metadata_key = str(token_cfg["metadata_key"])
            env_name = str(token_cfg["key_env_var"])
        except (KeyError, TypeError, ValueError):
            return {"status": "invalid settings", "detected": False}
        token_ids = ctx.metadata.get(metadata_key)
        if token_ids is None:
            return {"status": "not available (the pipeline did not pass token ids)", "detected": False}
        if not isinstance(token_ids, (list, tuple)) or not all(isinstance(t, int) for t in token_ids):
            return {"status": "invalid token ids", "detected": False}
        key = os.environ.get(env_name)
        if not key:
            return {"status": f"not checked ({env_name} is not set)", "detected": False}
        result = detect_token_watermark(list(token_ids), key, gamma, z_threshold, min_tokens)
        result["status"] = "detected" if result["detected"] else ("text too short" if result["note"] == "too_short" else "not detected")
        return result

    def _verdict(self, status: str, score: float, reason: str, evidence: dict) -> Verdict:
        return Verdict(control_id=self.control_id, domain=self.domain, status=status,
                       risk_score=score, reason=reason, evidence=evidence)
