"""
domains/domain4_output_risk/controls/or_003_output_watermark.py

QSAF-OR-003: Token-based watermarking for response traceability (auditable, egress).

Phase 1 design (the team's choice, documented in the README):
  We do NOT change the words of the reply. Instead we compute a FINGERPRINT:
      HMAC-SHA256( secret key , session_id + reply )
  and put it in the Verdict evidence, so it lands in the audit log.
  Later, anyone holding the key can take a reply text and its session id,
  recompute the fingerprint, and check whether our system produced it
  (see verify_fingerprint below).

Real token-level watermarking (nudging the model's word choices) needs access
to the model's internals, so it is future work for self-hosted models.

The secret key is read from an ENVIRONMENT VARIABLE named in policy.yaml.
It is never stored in the code or the repo.
"""

import hashlib
import hmac
import os

from core.control_base import Control
from core.models import RequestContext, Verdict
from core.policy_loader import load_domain_policy

POLICY_FOLDER = "domain4_output_risk"
POLICY_KEY = "or_003_watermark"


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
        note = "" if key else f" Set {env_name} for a signed (tamper-proof) fingerprint."
        return self._verdict(
            "pass", 0.0,
            f"Response fingerprint {fingerprint[:12]}... recorded for traceability ({mode}).{note}",
            {"fingerprint": fingerprint, "mode": mode, "key_id": key_id if key else None, "reply_length": len(str(reply))},
        )

    def _verdict(self, status: str, score: float, reason: str, evidence: dict) -> Verdict:
        return Verdict(control_id=self.control_id, domain=self.domain, status=status,
                       risk_score=score, reason=reason, evidence=evidence)
