"""Single source of truth for the dashboard permission matrix.

Group taxonomy (sourced from FreeIPA, federated into Keycloak):

* platform-engineer  - full control of the platform
* sre-oncall         - operational duties: break-glass, JIT request, security
* security-auditor   - read-only across the board, can approve/revoke JIT
* developer          - can request JIT for themselves, browse own sessions
* viewer             - landing page + posture only

Permissions are dot-namespaced strings. The frontend imports them through the
`/api/v1/auth/permissions` endpoint so the matrix lives in exactly one place.

Naming convention: `<domain>:<action>`

The Backend uses these strings inside `require_permission(...)` dependencies.
The Frontend uses them inside `auth.can(...)` helpers and as `meta.requires`
on routes.
"""

from __future__ import annotations

from typing import Dict, FrozenSet, Iterable, List

# ---------------------------------------------------------------------------
# Permission catalogue (all strings ever referenced anywhere)
# ---------------------------------------------------------------------------
P_OVERVIEW_READ = "overview:read"

P_JIT_REQUEST = "jit:request"
P_JIT_READ = "jit:read"
P_JIT_READ_OWN = "jit:read-own"
P_JIT_APPROVE = "jit:approve"
P_JIT_REVOKE = "jit:revoke"
P_JIT_POLICY_WRITE = "jit:policy:write"

P_IAM_READ = "iam:read"
P_IAM_WRITE = "iam:write"

P_APPS_READ = "apps:read"
P_APPS_WRITE = "apps:write"

P_SECRETS_READ = "secrets:read"
P_SECRETS_WRITE = "secrets:write"

P_SCA_READ = "sca:read"

P_SECURITY_READ = "security:read"
P_SECURITY_WRITE = "security:write"

P_BREAKGLASS_READ = "breakglass:read"
P_BREAKGLASS_ISSUE = "breakglass:issue"
P_BREAKGLASS_REVOKE = "breakglass:revoke"

# ---------------------------------------------------------------------------
# Group → permission set
# ---------------------------------------------------------------------------
GROUP_TO_PERMISSIONS: Dict[str, FrozenSet[str]] = {
    "platform-engineer": frozenset({
        P_OVERVIEW_READ,
        P_JIT_REQUEST, P_JIT_READ, P_JIT_READ_OWN,
        P_JIT_APPROVE, P_JIT_REVOKE, P_JIT_POLICY_WRITE,
        P_IAM_READ, P_IAM_WRITE,
        P_APPS_READ, P_APPS_WRITE,
        P_SECRETS_READ, P_SECRETS_WRITE,
        P_SCA_READ,
        P_SECURITY_READ, P_SECURITY_WRITE,
        P_BREAKGLASS_READ, P_BREAKGLASS_ISSUE, P_BREAKGLASS_REVOKE,
    }),
    "sre-oncall": frozenset({
        P_OVERVIEW_READ,
        P_JIT_REQUEST, P_JIT_READ, P_JIT_READ_OWN,
        P_IAM_READ,
        P_APPS_READ,
        P_SECRETS_READ,
        P_SCA_READ,
        P_SECURITY_READ, P_SECURITY_WRITE,
        P_BREAKGLASS_READ, P_BREAKGLASS_ISSUE, P_BREAKGLASS_REVOKE,
    }),
    "security-auditor": frozenset({
        P_OVERVIEW_READ,
        P_JIT_READ, P_JIT_APPROVE, P_JIT_REVOKE,
        P_IAM_READ,
        P_APPS_READ,
        P_SECRETS_READ,
        P_SCA_READ,
        P_SECURITY_READ, P_SECURITY_WRITE,
        P_BREAKGLASS_READ,
    }),
    "developer": frozenset({
        P_OVERVIEW_READ,
        P_JIT_REQUEST, P_JIT_READ_OWN,
        P_APPS_READ,
        P_SCA_READ,
    }),
    "viewer": frozenset({
        P_OVERVIEW_READ,
        P_SECURITY_READ,
    }),
}

ALL_GROUPS: List[str] = sorted(GROUP_TO_PERMISSIONS.keys())
ALL_PERMISSIONS: FrozenSet[str] = frozenset().union(*GROUP_TO_PERMISSIONS.values())


def permissions_for(groups: Iterable[str]) -> FrozenSet[str]:
    """Compute the union of permissions over the given group memberships.

    Unknown group names are silently ignored. Useful when LDAP/Keycloak
    introduces ad-hoc groups that the dashboard does not (yet) understand.
    """
    out: set[str] = set()
    for g in groups or []:
        out |= GROUP_TO_PERMISSIONS.get(g, frozenset())
    return frozenset(out)


def groups_granting(permission: str) -> List[str]:
    """Return the list of groups that grant a given permission. Used by the
    Unauthorized.vue page to tell the user what they need to ask for."""
    return sorted(g for g, perms in GROUP_TO_PERMISSIONS.items() if permission in perms)


__all__ = [
    "ALL_GROUPS",
    "ALL_PERMISSIONS",
    "GROUP_TO_PERMISSIONS",
    "groups_granting",
    "permissions_for",
    # individual permission constants exported for direct import in routes:
    "P_OVERVIEW_READ",
    "P_JIT_REQUEST", "P_JIT_READ", "P_JIT_READ_OWN", "P_JIT_APPROVE", "P_JIT_REVOKE",
    "P_JIT_POLICY_WRITE",
    "P_IAM_READ", "P_IAM_WRITE",
    "P_APPS_READ", "P_APPS_WRITE",
    "P_SECRETS_READ", "P_SECRETS_WRITE",
    "P_SCA_READ",
    "P_SECURITY_READ", "P_SECURITY_WRITE",
    "P_BREAKGLASS_READ", "P_BREAKGLASS_ISSUE", "P_BREAKGLASS_REVOKE",
]
