"""
domains/domain2_role_context/controls/__init__.py

Registers every control in this domain so the orchestrator can find them.
When you finish implementing a control for real, you do NOT need to
change this file — the class stays the same, only its internals change.
"""

from domains.domain2_role_context.controls.rc_001_role_lock import RoleLockRC001
from domains.domain2_role_context.controls.rc_002_impersonation_detector import ImpersonationDetectorRC002
from domains.domain2_role_context.controls.rc_003_context_drift import ContextDriftRC003
from domains.domain2_role_context.controls.rc_004_session_pivot import SessionPivotRC004
from domains.domain2_role_context.controls.rc_005_nested_injection import NestedInjectionRC005
from domains.domain2_role_context.controls.rc_006_role_assertion_log import RoleAssertionLogRC006
from domains.domain2_role_context.controls.rc_007_context_integrity import ContextIntegrityRC007

ALL_CONTROLS = [
    RoleLockRC001(),
    ImpersonationDetectorRC002(),
    ContextDriftRC003(),
    SessionPivotRC004(),
    NestedInjectionRC005(),
    RoleAssertionLogRC006(),
    ContextIntegrityRC007(),
]
