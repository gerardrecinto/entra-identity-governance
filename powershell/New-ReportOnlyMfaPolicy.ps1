# Create a Conditional Access policy that requires MFA for privileged roles, in report-only mode first.
# Needs: Connect-MgGraph -Scopes Policy.ReadWrite.ConditionalAccess
param([Parameter(Mandatory)][string]$BreakGlassGroupId)
$ErrorActionPreference = "Stop"

$policy = @{
    displayName   = "Require MFA for privileged roles"
    state         = "enabledForReportingButNotEnforced"   # watch the sign-in logs, then switch to enabled
    conditions    = @{
        users        = @{
            includeRoles  = @(
                "62e90394-69f5-4237-9190-012177145e10",
                "e8611ab8-c189-46e8-94e1-60213ab1f814",
                "194ae4cb-b126-40b2-bd5b-6091b380977d")
            excludeGroups = @($BreakGlassGroupId)
        }
        applications = @{ includeApplications = @("All") }
    }
    grantControls = @{ operator = "OR"; builtInControls = @("mfa") }
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $policy
