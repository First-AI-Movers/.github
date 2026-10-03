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
OPERATOR_APPROVAL_CONTEXT_CHANGED = "OPERATOR_APPROVAL_CONTEXT_CHANGED"
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

#: What the collector found about the pull request when it read the reviews. Only ``CURRENT`` can admit:
#: the pull request, read fresh, still has the evaluated head and the very body the rest of the gate judges.
#: A re-run replays its original event, so a body edited since then (a grant marker added, say) must not be
#: judged as if it were still the old one; the machine pushes again and a fresh run reads the new body.
CONTEXT_CURRENT = "CURRENT"
CONTEXT_UNREAD = "UNREAD"
CONTEXT_HEAD_MOVED = "HEAD_MOVED"
CONTEXT_BODY_CHANGED = "BODY_CHANGED"
CONTEXTS = (CONTEXT_CURRENT, CONTEXT_UNREAD, CONTEXT_HEAD_MOVED, CONTEXT_BODY_CHANGED)


def enabled(binding) -> bool:
    """Whether the trusted binding switches the route on. The workflow collects nothing otherwise."""
    return isinstance(binding, dict) and binding.get("activation") == "enabled"


def validate_binding(binding) -> None:
    """``ValueError`` unless ``binding`` is exactly ``{schema, activation}``."""
    if (not isinstance(binding, dict) or set(binding) != {"schema", "activation"}
            or binding.get("schema") != SCHEMA or binding.get("activation") not in ACTIVATIONS):
        raise ValueError(f"operator_approval must be {{schema: {SCHEMA!r}, activation: enabled|disabled}}")


def collect(api, repository: str, number, head_sha, body) -> dict:
    """``{"context", "reviews"}`` for one pull request, as the judge reads it.

    ``head_sha`` and ``body`` are what the run's event recorded. The pull request is read fresh before AND after
    the reviews, and both reads must still show that head and that body: an edit that lands while the reviews
    are being read is never recorded as ``CURRENT``. ``reviews`` is ``None`` unless the context is ``CURRENT``
    and every page was read. ``api(path)`` is the workflow's read-only ``gh api`` call, returning parsed JSON or
    ``None``; any exception it raises is the caller's to record as ``UNREAD``."""
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        return {"context": CONTEXT_UNREAD, "reviews": None}
    before = _context(api(f"repos/{repository}/pulls/{number}"), head_sha, body)
    if before != CONTEXT_CURRENT:
        return {"context": before, "reviews": None}
    reviews = _reviews(api, repository, number)
    after = _context(api(f"repos/{repository}/pulls/{number}"), head_sha, body)
    if after != CONTEXT_CURRENT:
        return {"context": after, "reviews": None}
    return {"context": CONTEXT_CURRENT, "reviews": reviews}


def _context(current, head_sha, body) -> str:
    """Whether one fresh read of the pull request still shows the event's head and body."""
    if not isinstance(current, dict) or not isinstance(current.get("head"), dict):
        return CONTEXT_UNREAD
    if current["head"].get("sha") != head_sha:
        return CONTEXT_HEAD_MOVED
    if (current.get("body") or "") != (body or ""):
        return CONTEXT_BODY_CHANGED
    return CONTEXT_CURRENT


def _reviews(api, repository: str, number: int) -> list | None:
    """Every review, or ``None`` when the read is not complete."""
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
    approval = pr.get("approval")
    if not isinstance(approval, dict) or approval.get("context") not in CONTEXTS:
        return OPERATOR_APPROVAL_REVIEWS_UNREADABLE
    if approval["context"] in (CONTEXT_HEAD_MOVED, CONTEXT_BODY_CHANGED):
        return OPERATOR_APPROVAL_CONTEXT_CHANGED
    reviews = approval.get("reviews")
    if (approval["context"] != CONTEXT_CURRENT or not isinstance(reviews, list)
            or not all(_well_formed(r) for r in reviews)):
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
