"""Shared helper for Domain 1: one place that decides which text a control inspects."""
from core.models import RequestContext


def get_cleaned_prompt(ctx: RequestContext) -> str:
    """Return the sanitized prompt.

    Uses ctx.metadata["cleaned_prompt"] when a caller (for example demo_domain1.py) already
    set it. Otherwise sanitizes ctx.raw_prompt itself, so a control gets clean text even when
    PI-008 has not run before it or the caller never copied its result. Never mutates ctx.
    """
    cleaned = ctx.metadata.get("cleaned_prompt")
    if isinstance(cleaned, str):
        return cleaned
    # Imported here, not at the top: the controls package imports this module, so a top-level
    # import of a control here would create a circular import.
    from domains.domain1_prompt_injection.controls.pi_008_token_sanitizer import sanitize_prompt
    return sanitize_prompt(ctx.raw_prompt)[0]