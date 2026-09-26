"""
domains/domain4_output_risk/controls/__init__.py

Registers every control in this domain so the orchestrator can find them.
When you finish implementing a control for real, you do NOT need to
change this file — the class stays the same, only its internals change.
"""

from domains.domain4_output_risk.controls.or_001_jailbreak_output_filter import JailbreakOutputFilterOR001
from domains.domain4_output_risk.controls.or_002_hallucination_flag import HallucinationFlagOR002
from domains.domain4_output_risk.controls.or_003_output_watermark import OutputWatermarkOR003
from domains.domain4_output_risk.controls.or_004_sensitivity_scoring import SensitivityScoringOR004
from domains.domain4_output_risk.controls.or_005_risky_reroute import RiskyRerouteOR005
from domains.domain4_output_risk.controls.or_006_prompt_response_correlation import PromptResponseCorrelationOR006
from domains.domain4_output_risk.controls.or_007_tone_deviation import ToneDeviationOR007

ALL_CONTROLS = [
    JailbreakOutputFilterOR001(),
    HallucinationFlagOR002(),
    OutputWatermarkOR003(),
    SensitivityScoringOR004(),
    RiskyRerouteOR005(),
    PromptResponseCorrelationOR006(),
    ToneDeviationOR007(),
]
