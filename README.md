# entra-identity-governance

Identity checks and automation for Microsoft Entra ID: validate OIDC tokens correctly, lint Conditional Access, find standing admin roles that should be PIM-eligible, plan joiner/mover/leaver changes, and onboard privileged accounts to CyberArk.

| Area | Files |
|---|---|
| OIDC, OAuth 2.0, SSO, CIAM sign-in | `identity/oidc.py`: authorization code flow with PKCE, and ID token validation (RS256 only, issuer, audience, expiry, nonce, tenant) |
| SAML | `identity/saml.py`: issuer, audience, and time-window checks on an assertion, parsed with `defusedxml` |
| Conditional Access, MFA | `identity/ca_lint.py` lints exported policies: MFA for admin roles, legacy auth blocked, break-glass excluded, report-only is not counted as enforced |
| PIM, RBAC | `identity/pim_audit.py` reads Microsoft Graph role schedule instances and flags standing privileged assignments |
| Identity lifecycle | `identity/lifecycle.py` compares the HR feed with Entra and returns create, move, disable, enable, and review actions. It never deletes. |
| CyberArk | `identity/cyberark.py` builds and sends the PVWA logon and account onboarding calls, with rotation on |
| PowerShell and Microsoft Graph | `powershell/`: standing admins, a report-only MFA policy, stale guests for access reviews |
| Terraform | `terraform/main.tf`: two Conditional Access policies (report-only), a group, and an Azure RBAC role assignment |

```bash
pip install -r requirements.txt
python -m pytest -q tests
```

## Verified
- 17 pytest tests pass. They cover the RFC 7636 PKCE test vector, rejection of wrong audience, issuer, nonce, tenant, expired, `alg=none`, and HS256 tokens, a SAML DTD attack, Conditional Access gaps, the lifecycle plan, PIM filtering, Graph paging, and the CyberArk calls against local stub servers.
- `terraform fmt` is clean.

## Not verified
- Nothing ran against a real Entra tenant, Graph, or CyberArk. The Graph and PVWA calls were tested against stubs shaped from the documented API.
- The PowerShell scripts were not run (no PowerShell here) and need the Microsoft.Graph module and consent to the listed scopes.
- `terraform validate` was not run. The resource arguments come from the azuread provider docs and were not applied. Both policies start report-only on purpose.
- SAML signature verification is not implemented. Use `python3-saml` or `xmlsec` first, then these checks.
- Entra ID Governance entitlement management (access packages) is not covered. `Get-StaleGuests.ps1` only produces the input for an access review.
