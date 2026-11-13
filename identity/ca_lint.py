"""Lint Conditional Access policies exported from Microsoft Graph (conditionalAccessPolicy JSON)."""

ADMIN_ROLES = {  # built-in role template ids: Global Administrator, Privileged Role Administrator, Security Administrator
    "62e90394-69f5-4237-9190-012177145e10", "e8611ab8-c189-46e8-94e1-60213ab1f814", "194ae4cb-b126-40b2-bd5b-6091b380977d",
}


def lint(policies, break_glass_group):
    out = []
    enabled = [p for p in policies if p["state"] != "disabled"]

    for p in enabled:
        c, g = p["conditions"], p.get("grantControls") or {}
        users = c["users"]
        if users.get("includeUsers") == ["All"] and c["applications"].get("includeApplications") == ["All"]:
            if break_glass_group not in users.get("excludeGroups", []):
                out.append(f"{p['displayName']}: applies to everyone and every app with no break-glass exclusion (lockout risk)")
        if p["state"] == "enabled" and not g.get("builtInControls") and not g.get("authenticationStrength"):
            out.append(f"{p['displayName']}: enabled with no grant control")

    def has(pred):
        return any(pred(p) and p["state"] == "enabled" for p in enabled)

    if not has(lambda p: set(p["conditions"]["users"].get("includeRoles", [])) >= ADMIN_ROLES
               and "mfa" in (p.get("grantControls") or {}).get("builtInControls", [])):
        out.append("no enabled policy requires MFA for the privileged admin roles")
    if not has(lambda p: set(p["conditions"].get("clientAppTypes", [])) >= {"exchangeActiveSync", "other"}
               and "block" in (p.get("grantControls") or {}).get("builtInControls", [])):
        out.append("no enabled policy blocks legacy authentication")
    return out
