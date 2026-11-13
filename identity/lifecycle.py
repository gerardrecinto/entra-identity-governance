"""Joiner, mover, leaver: compare the HR feed with Entra ID and return the actions to take."""

DISABLE_AFTER_DAYS = 0  # leavers are disabled on their last day, deleted by Entra after 30 days in the recycle bin


def plan(hr, entra, today):
    """hr: [{id, email, dept, status, end_date}], entra: [{id, mail, dept, enabled, groups}].

    Returns a list of (action, id, detail). Never deletes: a leaver is disabled and their sessions revoked.
    """
    users = {u["id"]: u for u in entra}
    out = []
    for p in hr:
        u = users.get(p["id"])
        active = p["status"] == "active" and not (p.get("end_date") and p["end_date"] <= today)
        if u is None:
            if active:
                out.append(("create", p["id"], p["email"]))
            continue
        if not active and u["enabled"]:
            out.append(("disable", p["id"], "revoke sessions and remove from all groups"))
        elif active and u["dept"] != p["dept"]:
            out.append(("move", p["id"], f"{u['dept']} -> {p['dept']}: swap department groups, review access"))
        elif active and not u["enabled"]:
            out.append(("enable", p["id"], "rehire or leave ended"))
    hr_ids = {p["id"] for p in hr}
    for u in entra:
        if u["id"] not in hr_ids and u["enabled"]:
            out.append(("review", u["id"], "enabled in Entra with no HR record"))
    return out
