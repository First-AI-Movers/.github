"""The operator's approval of an exact machine-authored change (agent-toolkit #3052, paperwork removal).

Before this, the only evidence of the operator these routes had was his own account performing the mechanics:
authoring and running a pull request against the judge, or authoring a ``standing-authority/v2`` block for a
protected path. A machine could not do those steps without the merged record claiming a personal act that
never happened. This module lets the machine do the mechanics and keeps the decision his: a machine-authored,
machine-run, machine-committed pull request is admitted when the latest decisive review by a pinned operator
principal is ``APPROVED`` on exactly the head being judged.

The identity standard is unchanged: the same pinned operator logins, of type User, and nothing else. What is
bound is narrower than an authority envelope: one commit. Any later push makes the approval stale, and a later
``CHANGES_REQUESTED`` or a dismissal revokes it. The machine never approves; GitHub never lets a pull request's
author approve it.

Pure stdlib. ``collect`` runs in the trusted workflow with the job's read-only token; ``refusal`` is
networkless and judges only the recorded evidence. Every refusal is one typed reason.
"""
from __future__ import annotations

import re

SCHEMA = "aeos-operator-approval/v1"
ACTIVATIONS = ("enabled", "disabled")

OPERATOR_APPROVAL_UNBOUND = "OPERATOR_APPROVAL_UNBOUND"
OPERATOR_APPROVAL_DISABLED = "OPERATOR_APPROVAL_DISABLED"
OPERATOR_APPROVAL_EVENT_UNPROVABLE = "OPERATOR_APPROVAL_EVENT_UNPROVABLE"
OPERATOR_APPROVAL_AUTHOR_NOT_MACHINE = "OPERATOR_APPROVAL_AUTHOR_NOT_MACHINE"
OPERATOR_APPROVAL_TRIGGER_NOT_MACHINE = "OPERATOR_APPROVAL_TRIGGER_NOT_MACHINE"
OPERATOR_APPROVAL_HEAD_COMMIT_NOT_MACHINE = "OPERATOR_APPROVAL_HEAD_COMMIT_NOT_MACHINE"
OPERATOR_APPROVAL_REPOSITORY_MISMATCH = "OPERATOR_APPROVAL_REPOSITORY_MISMATCH"
OPERATOR_APPROVAL_HEAD_MISMATCH = "OPERATOR_APPROVAL_HEAD_MISMATCH"
OPERATOR_APPROVAL_REVIEWS_UNREADABLE = "OPERATOR_APPROVAL_REVIEWS_UNREADABLE"
OPERATOR_APPROVAL_ABSENT = "OPERATOR_APPROVAL_ABSENT"
OPERATOR_APPROVAL_NOT_APPROVED = "OPERATOR_APPROVAL_NOT_APPROVED"
OPERATOR_APPROVAL_STALE_HEAD = "OPERATOR_APPROVAL_STALE_HEAD"

#: The review states that decide; ``COMMENTED`` and ``PENDING`` never do.
DECISIVE_STATES = frozenset({"APPROVED", "CHANGES_REQUESTED", "DISMISSED"})
REVIEW_STATES = DECISIVE_STATES | {"COMMENTED", "PENDING"}
#: A complete read is at most this many pages of 100; one more full page is unreadable, never "no review".
MAX_REVIEW_PAGES = 3
PAGE_SIZE = 100

_SHA = re.compile(r"[0-9a-f]{40}")
_STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_REVIEW_KEYS = frozenset({"id", "login", "type", "state", "commit_id", "submitted_at"})


def validate_binding(binding) -> None:
    """``ValueError`` unless ``binding`` is exactly ``{schema, activation}``."""
    if (not isinstance(binding, dict) or set(binding) != {"schema", "activation"}
            or binding.get("schema") != SCHEMA or binding.get("activation") not in ACTIVATIONS):
        raise ValueError(f"operator_approval must be {{schema: {SCHEMA!r}, activation: enabled|disabled}}")


def collect(api, repository: str, number) -> list | None:
    """Every review of one pull request, as the judge reads it, or ``None`` when the read is not complete.

    ``api(path)`` is the workflow's read-only ``gh api`` call, returning parsed JSON or ``None``."""
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        return None
    reviews: list = []
    for page in range(1, MAX_REVIEW_PAGES + 1):
        rows = api(f"repos/{repository}/pulls/{number}/reviews?per_page={PAGE_SIZE}&page={page}")
        if not isinstance(rows, list):
            return None
        for row in rows:
            if not isinstance(row, dict):
                return None
            user = row.get("user") if isinstance(row.get("user"), dict) else {}
            reviews.append({"id": row.get("id"), "login": user.get("login"), "type": user.get("type"),
                            "state": row.get("state"), "commit_id": row.get("commit_id"),
                            "submitted_at": row.get("submitted_at")})
        if len(rows) < PAGE_SIZE:
            return reviews
    return None


def _well_formed(review) -> bool:
    if not isinstance(review, dict) or set(review) != _REVIEW_KEYS:
        return False
    if type(review["id"]) is not int or review["id"] < 1 or review["state"] not in REVIEW_STATES:
        return False
    if review["state"] in DECISIVE_STATES:
        return (isinstance(review["login"], str) and isinstance(review["type"], str)
                and isinstance(review["commit_id"], str) and _SHA.fullmatch(review["commit_id"]) is not None
                and isinstance(review["submitted_at"], str) and _STAMP.fullmatch(review["submitted_at"]) is not None)
    return True


def refusal(policy, evidence, repository: str, head_sha: str) -> str | None:
    """``None`` when the operator approved exactly this machine-authored head; otherwise the ONE typed reason.

    ``policy`` carries ``operator_approval`` (the trusted binding), ``machine_principals`` as ``(login, type)``
    pairs and ``operator_principals``. ``evidence`` is the trusted workflow's ``aeos-actor-evidence/v1``."""
    binding = getattr(policy, "operator_approval", None)
    if binding is None:
        return OPERATOR_APPROVAL_UNBOUND
    if binding.get("activation") != "enabled":
        return OPERATOR_APPROVAL_DISABLED
    # A merge-group run judges the queue's commit, which no review can name, so it is never provable here.
    if (not isinstance(evidence, dict) or evidence.get("event") != "pull_request"
            or not isinstance(evidence.get("pull_request"), dict)):
        return OPERATOR_APPROVAL_EVENT_UNPROVABLE
    pr = evidence["pull_request"]
    machines = set(policy.machine_principals)
    machine_logins = {login for login, _kind in machines}
    if (pr.get("author_login"), pr.get("author_type")) not in machines:
        return OPERATOR_APPROVAL_AUTHOR_NOT_MACHINE
    # The machine runs it and commits its head: an operator push or reopen is judged by the predecessor rule.
    if evidence.get("actor") not in machine_logins:
        return OPERATOR_APPROVAL_TRIGGER_NOT_MACHINE
    if pr.get("head_commit_author_login") not in machine_logins:
        return OPERATOR_APPROVAL_HEAD_COMMIT_NOT_MACHINE
    if (not isinstance(evidence.get("repository"), str) or not isinstance(repository, str)
            or evidence["repository"].strip().lower() != repository.strip().lower()):
        return OPERATOR_APPROVAL_REPOSITORY_MISMATCH
    head = (head_sha or "").strip().lower()
    if _SHA.fullmatch(head) is None or pr.get("head_sha") != head:
        return OPERATOR_APPROVAL_HEAD_MISMATCH
    reviews = pr.get("reviews")
    if not isinstance(reviews, list) or not all(_well_formed(r) for r in reviews):
        return OPERATOR_APPROVAL_REVIEWS_UNREADABLE
    ids = [r["id"] for r in reviews]
    if len(ids) != len(set(ids)):
        return OPERATOR_APPROVAL_REVIEWS_UNREADABLE
    operators = policy.operator_principals
    decisive = [r for r in reviews
                if r["state"] in DECISIVE_STATES and r["type"] == "User" and r["login"] in operators]
    if not decisive:
        return OPERATOR_APPROVAL_ABSENT
    latest = max(decisive, key=lambda r: (r["submitted_at"], r["id"]))
    if latest["state"] != "APPROVED":
        return OPERATOR_APPROVAL_NOT_APPROVED
    if latest["commit_id"] != head:
        return OPERATOR_APPROVAL_STALE_HEAD
    return None
