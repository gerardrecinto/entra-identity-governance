# Guest accounts with no sign-in for N days: input for an access review.
# Needs: Connect-MgGraph -Scopes User.Read.All,AuditLog.Read.All
param([int]$Days = 90)
$ErrorActionPreference = "Stop"

$cutoff = (Get-Date).AddDays(-$Days)
Get-MgUser -Filter "userType eq 'Guest'" -All -Property Id, UserPrincipalName, SignInActivity, CreatedDateTime |
    Where-Object {
        $last = $_.SignInActivity.LastSignInDateTime
        ($last -and $last -lt $cutoff) -or (-not $last -and $_.CreatedDateTime -lt $cutoff)
    } |
    Select-Object UserPrincipalName, @{ n = "LastSignIn"; e = { $_.SignInActivity.LastSignInDateTime } }
