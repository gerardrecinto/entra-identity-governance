"""OIDC with Microsoft Entra ID: PKCE for the sign-in request, strict validation of the ID token."""
import base64
import hashlib
import os
import urllib.parse

import jwt  # PyJWT


def pkce_pair():
    """RFC 7636 S256. Keep the verifier server side, send only the challenge."""
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    return verifier, challenge(verifier)


def challenge(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def authorize_url(tenant, client_id, redirect_uri, state, nonce, code_challenge, scope="openid profile email"):
    q = urllib.parse.urlencode({
        "client_id": client_id, "response_type": "code", "redirect_uri": redirect_uri, "scope": scope,
        "state": state, "nonce": nonce, "code_challenge": code_challenge, "code_challenge_method": "S256",
    })
    return f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?{q}"


def validate_id_token(token, jwks_client, tenant_id, client_id, nonce):
    """Signature, issuer, audience, expiry, and nonce. Only RS256 is accepted, never `none` or HS256."""
    key = jwks_client.get_signing_key_from_jwt(token).key
    claims = jwt.decode(
        token, key, algorithms=["RS256"], audience=client_id,
        issuer=f"https://login.microsoftonline.com/{tenant_id}/v2.0",
        options={"require": ["exp", "iat", "iss", "aud", "sub"]},
    )
    if claims.get("nonce") != nonce:
        raise jwt.InvalidTokenError("nonce mismatch")
    if claims.get("tid") != tenant_id:
        raise jwt.InvalidTokenError("token is from another tenant")
    return claims
