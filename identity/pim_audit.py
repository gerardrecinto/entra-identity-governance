"""Find privileged roles assigned permanently, which should be eligible through PIM instead.

Reads Microsoft Graph /roleManagement/directory/roleAssignmentScheduleInstances. An instance with
assignmentType Assigned and no end date is a standing assignment. Activated ones came through PIM.
"""
import json
import urllib.request

PRIVILEGED = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
}


def standing_assignments(instances, allow_principals=()):
    return [
        (PRIVILEGED[i["roleDefinitionId"]], i["principalId"])
        for i in instances
        if i["roleDefinitionId"] in PRIVILEGED
        and i["assignmentType"] == "Assigned"
        and not i.get("endDateTime")
        and i["principalId"] not in allow_principals  # break-glass accounts
    ]


def fetch(token, base="https://graph.microsoft.com/v1.0"):
    url = f"{base}/roleManagement/directory/roleAssignmentScheduleInstances"
    items = []
    while url:
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=20) as r:
            page = json.load(r)
        items += page["value"]
        url = page.get("@odata.nextLink")
    return items
