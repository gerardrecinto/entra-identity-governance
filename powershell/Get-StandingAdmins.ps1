# List permanent (non-PIM) assignments of the highest privileged Entra roles.
# Needs: Install-Module Microsoft.Graph.Identity.Governance, and Connect-MgGraph -Scopes RoleManagement.Read.Directory
param([string[]]$BreakGlass = @())
$ErrorActionPreference = "Stop"

$privileged = @{
    "62e90394-69f5-4237-9190-012177145e10" = "Global Administrator"
    "e8611ab8-c189-46e8-94e1-60213ab1f814" = "Privileged Role Administrator"
    "194ae4cb-b126-40b2-bd5b-6091b380977d" = "Security Administrator"
}

Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All |
    Where-Object {
        $privileged.ContainsKey($_.RoleDefinitionId) -and
        $_.AssignmentType -eq "Assigned" -and
        -not $_.EndDateTime -and
        $BreakGlass -notcontains $_.PrincipalId
    } |
    ForEach-Object { [pscustomobject]@{ Role = $privileged[$_.RoleDefinitionId]; PrincipalId = $_.PrincipalId } }
