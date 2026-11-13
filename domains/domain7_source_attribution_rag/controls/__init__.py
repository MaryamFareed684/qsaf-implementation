from domains.domain7_source_attribution_rag.controls.sa_001_source_tracking import SourceTrackingSA001
from domains.domain7_source_attribution_rag.controls.sa_002_response_vs_docs import ResponseVsDocsSA002
from domains.domain7_source_attribution_rag.controls.sa_003_hallucination_score import HallucinationScoreSA003
from domains.domain7_source_attribution_rag.controls.sa_004_retrieval_relevance import RetrievalRelevanceSA004
from domains.domain7_source_attribution_rag.controls.sa_005_non_attributable_log import NonAttributableLogSA005
from domains.domain7_source_attribution_rag.controls.sa_006_source_trust import SourceTrustSA006
from domains.domain7_source_attribution_rag.controls.sa_007_auto_disable import AutoDisableSA007

ALL_CONTROLS = [
    SourceTrackingSA001(),
    ResponseVsDocsSA002(),
    HallucinationScoreSA003(),
    RetrievalRelevanceSA004(),
    NonAttributableLogSA005(),
    SourceTrustSA006(),
    AutoDisableSA007(),
]