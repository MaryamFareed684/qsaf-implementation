"""
domains/domain3_plugin_abuse/controls/__init__.py

Registers every control in this domain so the orchestrator can find them.
When you finish implementing a control for real, you do NOT need to
change this file — the class stays the same, only its internals change.
"""

from domains.domain3_plugin_abuse.controls.pl_001_tool_whitelist import ToolWhitelistPL001
from domains.domain3_plugin_abuse.controls.pl_002_command_tracking import CommandTrackingPL002
from domains.domain3_plugin_abuse.controls.pl_003_sensitive_tool_gate import SensitiveToolGatePL003
from domains.domain3_plugin_abuse.controls.pl_004_tool_anomaly import ToolAnomalyPL004
from domains.domain3_plugin_abuse.controls.pl_005_usage_correlation import UsageCorrelationPL005
from domains.domain3_plugin_abuse.controls.pl_006_rate_limiter import RateLimiterPL006
from domains.domain3_plugin_abuse.controls.pl_007_session_terminator import SessionTerminatorPL007

ALL_CONTROLS = [
    ToolWhitelistPL001(),
    CommandTrackingPL002(),
    SensitiveToolGatePL003(),
    ToolAnomalyPL004(),
    UsageCorrelationPL005(),
    RateLimiterPL006(),
    SessionTerminatorPL007(),
]
