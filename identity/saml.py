"""Conditions checks for a SAML assertion. Signature verification is not done here: use xmlsec or
python3-saml for that, and run these checks only on an assertion whose signature already verified."""
from datetime import datetime, timezone

from defusedxml import ElementTree as ET

NS = {"s": "urn:oasis:names:tc:SAML:2.0:assertion"}


def _t(v):
    return datetime.fromisoformat(v.replace("Z", "+00:00"))


def check_assertion(xml, issuer, audience, now=None, skew_seconds=60):
    """Return a list of problems. Empty means the conditions hold."""
    now = now or datetime.now(timezone.utc)
    root = ET.fromstring(xml)  # defusedxml refuses DTDs and entity tricks
    out = []
    if (root.findtext("s:Issuer", namespaces=NS) or "").strip() != issuer:
        out.append("wrong issuer")
    cond = root.find("s:Conditions", NS)
    if cond is None:
        return out + ["no Conditions element"]
    nb, na = cond.get("NotBefore"), cond.get("NotOnOrAfter")
    if not na:
        out.append("no NotOnOrAfter")
    elif now.timestamp() - skew_seconds >= _t(na).timestamp():
        out.append("assertion expired")
    if nb and now.timestamp() + skew_seconds < _t(nb).timestamp():
        out.append("assertion not yet valid")
    auds = [a.text for a in cond.findall("s:AudienceRestriction/s:Audience", NS)]
    if audience not in auds:
        out.append("audience does not include this service provider")
    return out
