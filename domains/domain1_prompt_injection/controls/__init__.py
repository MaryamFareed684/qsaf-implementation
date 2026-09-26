"""
domains/domain1_prompt_injection/controls/__init__.py

Registers every control in this domain so the orchestrator can find them.
When you finish implementing a control for real, you do NOT need to
change this file — the class stays the same, only its internals change.
"""

from domains.domain1_prompt_injection.controls.pi_001_blacklist import BlacklistPI001
from domains.domain1_prompt_injection.controls.pi_002_dynamic_analysis import DynamicAnalysisPI002
from domains.domain1_prompt_injection.controls.pi_003_embedding_similarity import EmbeddingSimilarityPI003
from domains.domain1_prompt_injection.controls.pi_004_risk_scoring import RiskScoringPI004
from domains.domain1_prompt_injection.controls.pi_005_multi_phase_validator import MultiPhaseValidatorPI005
from domains.domain1_prompt_injection.controls.pi_006_escalation_router import EscalationRouterPI006
from domains.domain1_prompt_injection.controls.pi_007_token_anomaly import TokenAnomalyPI007
from domains.domain1_prompt_injection.controls.pi_008_token_sanitizer import TokenSanitizerPI008

ALL_CONTROLS = [
    BlacklistPI001(),
    DynamicAnalysisPI002(),
    EmbeddingSimilarityPI003(),
    RiskScoringPI004(),
    MultiPhaseValidatorPI005(),
    EscalationRouterPI006(),
    TokenAnomalyPI007(),
    TokenSanitizerPI008(),
]
