"""Onboard a privileged account into a CyberArk safe through the PVWA REST API."""
import json
import urllib.request


def _call(base, path, body, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = token
    req = urllib.request.Request(base + path, json.dumps(body).encode(), headers, method="POST")
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


def logon(base, user, password):
    return _call(base, "/PasswordVault/API/auth/CyberArk/Logon", {"username": user, "password": password})


def account_payload(name, address, user, safe, secret, platform="WinDomain"):
    """Rotation is on from day one, so the secret you pass in is replaced after onboarding."""
    if not safe.startswith("PRD-") and not safe.startswith("NPRD-"):
        raise ValueError("safe name must start with PRD- or NPRD-")
    return {
        "name": name, "address": address, "userName": user, "platformId": platform,
        "safeName": safe, "secretType": "password", "secret": secret,
        "secretManagement": {"automaticManagementEnabled": True},
    }


def onboard(base, token, payload):
    return _call(base, "/PasswordVault/API/Accounts", payload, token)
