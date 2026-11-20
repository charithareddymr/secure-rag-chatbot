"""Users, roles, and which document access levels each role may read.

Demo only: users are hard-coded and there are no passwords. In production the
role would come from a verified identity token (for example an OIDC ID token
from SSO), never from something the user types.
"""

# Deny by default: a role can read ONLY the access levels listed here
ROLE_PERMISSIONS = {
    "intern": ["public"],
    "security_team": ["public", "confidential"],
}

USERS = {
    "alex": "intern",
    "sam": "security_team",
}


def get_role(username):
    """Look up a user's role. Unknown users are rejected."""
    role = USERS.get(username.strip().lower())
    if role is None:
        raise PermissionError(f"Unknown user: {username!r}")
    return role


def allowed_access_levels(role):
    """Return the access levels a role may read. Unknown roles are rejected."""
    if role not in ROLE_PERMISSIONS:
        raise PermissionError(f"Unknown role: {role!r}")
    return list(ROLE_PERMISSIONS[role])  # a copy, so callers can't modify the policy
