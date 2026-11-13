import json
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from identity import ca_lint, cyberark, lifecycle, oidc, pim_audit, saml

TENANT, CLIENT = "tenant-1", "client-1"
NOW = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)


# ---- OIDC ----
def test_pkce_matches_the_rfc_7636_example():
    assert oidc.challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_authorize_url_carries_pkce_and_nonce():
    url = oidc.authorize_url(TENANT, CLIENT, "https://app/cb", "st", "no", "ch")
    assert "code_challenge_method=S256" in url and "nonce=no" in url and url.startswith("https://login.microsoftonline.com/tenant-1/")


KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeJwks:
    def get_signing_key_from_jwt(self, token):
        class K:
            key = KEY.public_key()
        return K


def token(**over):
    c = {"iss": f"https://login.microsoftonline.com/{TENANT}/v2.0", "aud": CLIENT, "sub": "u", "tid": TENANT,
         "nonce": "n1", "iat": datetime.now(timezone.utc) - timedelta(seconds=5), "exp": datetime.now(timezone.utc) + timedelta(minutes=5)}
    c.update(over)
    return jwt.encode(c, KEY, algorithm="RS256")


def check(t):
    return oidc.validate_id_token(t, FakeJwks(), TENANT, CLIENT, "n1")


def test_good_token_passes():
    assert check(token())["sub"] == "u"


@pytest.mark.parametrize("over", [
    {"aud": "other"}, {"iss": "https://evil/v2.0"}, {"nonce": "x"}, {"tid": "t2"},
    {"exp": datetime.now(timezone.utc) - timedelta(minutes=5)},
])
def test_bad_claims_are_rejected(over):
    with pytest.raises(jwt.InvalidTokenError):
        check(token(**over))


def test_alg_none_and_hs256_are_rejected():
    claims = {"iss": f"https://login.microsoftonline.com/{TENANT}/v2.0", "aud": CLIENT, "sub": "u", "tid": TENANT,
              "nonce": "n1", "iat": datetime.now(timezone.utc) - timedelta(seconds=5), "exp": datetime.now(timezone.utc) + timedelta(minutes=5)}
    for t in (jwt.encode(claims, None, algorithm="none"), jwt.encode(claims, "x" * 32, algorithm="HS256")):
        with pytest.raises(jwt.InvalidTokenError):
            check(t)


# ---- SAML ----
def assertion(not_on_or_after, audience="sp-1", issuer="idp-1"):
    return (f'<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><Issuer>{issuer}</Issuer>'
            f'<Conditions NotBefore="2026-11-13T11:00:00Z" NotOnOrAfter="{not_on_or_after}">'
            f'<AudienceRestriction><Audience>{audience}</Audience></AudienceRestriction></Conditions></Assertion>')


def test_saml_ok_expired_wrong_audience_and_dtd():
    assert saml.check_assertion(assertion("2026-11-13T13:00:00Z"), "idp-1", "sp-1", NOW) == []
    assert saml.check_assertion(assertion("2026-11-13T11:30:00Z"), "idp-1", "sp-1", NOW) == ["assertion expired"]
    assert "audience does not include this service provider" in saml.check_assertion(
        assertion("2026-11-13T13:00:00Z", audience="other"), "idp-1", "sp-1", NOW)
    with pytest.raises(Exception):
        saml.check_assertion('<!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>', "idp-1", "sp-1", NOW)


# ---- Conditional Access ----
ADMINS = sorted(ca_lint.ADMIN_ROLES)


def pol(name, state="enabled", users=None, apps=None, grant=None, clients=None):
    return {"displayName": name, "state": state,
            "conditions": {"users": users or {}, "applications": {"includeApplications": apps or ["All"]},
                           "clientAppTypes": clients or ["all"]},
            "grantControls": {"builtInControls": grant or []}}


def test_complete_baseline_has_no_findings():
    ps = [pol("admins mfa", users={"includeRoles": ADMINS, "excludeGroups": ["bg"]}, grant=["mfa"]),
          pol("block legacy", users={"includeUsers": ["All"], "excludeGroups": ["bg"]}, grant=["block"],
              clients=["exchangeActiveSync", "other"])]
    assert ca_lint.lint(ps, "bg") == []


def test_missing_baseline_and_lockout_risk_are_found():
    ps = [pol("everyone mfa", users={"includeUsers": ["All"]}, grant=["mfa"])]
    found = ca_lint.lint(ps, "bg")
    assert any("lockout" in f for f in found)
    assert any("privileged admin roles" in f for f in found)
    assert any("legacy authentication" in f for f in found)


def test_report_only_policy_does_not_count_as_enforced():
    ps = [pol("admins mfa", state="enabledForReportingButNotEnforced", users={"includeRoles": ADMINS}, grant=["mfa"])]
    assert any("privileged admin roles" in f for f in ca_lint.lint(ps, "bg"))


# ---- Lifecycle ----
def test_joiner_leaver_mover_and_orphan():
    hr = [{"id": "1", "email": "a@x", "dept": "eng", "status": "active"},
          {"id": "2", "email": "b@x", "dept": "eng", "status": "active", "end_date": "2026-11-13"},
          {"id": "3", "email": "c@x", "dept": "ops", "status": "active"}]
    entra = [{"id": "2", "dept": "eng", "enabled": True, "groups": []},
             {"id": "3", "dept": "eng", "enabled": True, "groups": []},
             {"id": "9", "dept": "eng", "enabled": True, "groups": []}]
    acts = {(a, i) for a, i, _ in lifecycle.plan(hr, entra, "2026-11-13")}
    assert acts == {("create", "1"), ("disable", "2"), ("move", "3"), ("review", "9")}


# ---- PIM ----
def test_standing_privileged_assignment_is_flagged_but_pim_activation_and_break_glass_are_not():
    ga = "62e90394-69f5-4237-9190-012177145e10"
    inst = [{"roleDefinitionId": ga, "principalId": "a", "assignmentType": "Assigned", "endDateTime": None},
            {"roleDefinitionId": ga, "principalId": "b", "assignmentType": "Activated", "endDateTime": "2026-11-13T20:00:00Z"},
            {"roleDefinitionId": ga, "principalId": "bg", "assignmentType": "Assigned", "endDateTime": None},
            {"roleDefinitionId": "other", "principalId": "c", "assignmentType": "Assigned", "endDateTime": None}]
    assert pim_audit.standing_assignments(inst, allow_principals={"bg"}) == [("Global Administrator", "a")]


def serve(handler):
    srv = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_graph_paging_follows_next_link():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            assert self.headers["Authorization"] == "Bearer t"
            base = f"http://127.0.0.1:{self.server.server_port}"
            body = ({"value": [1], "@odata.nextLink": base + "/p2"} if self.path.endswith("Instances")
                    else {"value": [2]})
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps(body).encode())

        def log_message(self, *a):
            pass

    srv = serve(H)
    assert pim_audit.fetch("t", base=f"http://127.0.0.1:{srv.server_port}") == [1, 2]
    srv.shutdown()


# ---- CyberArk ----
def test_cyberark_payload_rules_and_calls():
    with pytest.raises(ValueError):
        cyberark.account_payload("a", "h", "u", "random-safe", "s")
    seen = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            seen.append((self.path, self.headers.get("Authorization"), json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'"session-token"' if "Logon" in self.path else b'{"id":"1_2"}')

        def log_message(self, *a):
            pass

    srv = serve(H)
    base = f"http://127.0.0.1:{srv.server_port}"
    tok = cyberark.logon(base, "svc", "pw")
    out = cyberark.onboard(base, tok, cyberark.account_payload("db1", "10.0.0.5", "sa", "PRD-DB", "s3cret"))
    srv.shutdown()
    assert out == {"id": "1_2"} and seen[1][1] == "session-token"
    assert seen[1][2]["secretManagement"]["automaticManagementEnabled"] is True
