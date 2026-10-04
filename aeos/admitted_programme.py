"""A programme the operator admitted in trusted policy (agent-toolkit #3052): its operational carriers are system-owned.

The operator does not approve operational changes inside a programme he has already chosen. He decides ONCE, by
approving the policy change that adds the programme here, which protected files its machine-authored carriers may
change. After that, a carrier lands with no operator step when:

* it is machine-authored, machine-run and machine-committed (the machine route's own conjuncts, checked first);
* its body names exactly this programme (``<!-- aeos-programme: owner/repo#N -->``) and carries no grant marker;
* the programme Issue is open, authored by an operator principal (type User) and edited only by operators, read by
  the trusted workflow as for any programme;
* the pull request, read fresh by the trusted workflow before and after the reviews, still has the evaluated
  head and the very description the gate judges (the approval collector's ``CURRENT`` context): a re-run that
  replays an older description, say one without a grant marker, is refused;
* every protected path it changes, both sides of a rename, is listed EXACTLY in the entry's ``path_envelope``,
  and is a regular file on every side that exists (a symlink or gitlink at a listed path is never admitted).

An envelope never names a derivation root, a scoped-grant excluded path, anything under ``.github/`` or ``aeos/``, or
a path outside the derivation allowlist: the policy refuses to load an entry that does, and refuses any entry
at all when the scoped-grant exclusion list is not configured. So the envelope can only reach the ordinary
protected members it lists, never the trust machinery itself. Programme identity is case-insensitive in its
repository part, as GitHub's is. It lasts until revoked: the durable revocation is the policy entry itself
(``activation: disabled`` or removal); closing the programme Issue also stops every carrier, but only while it
stays closed. Widening an envelope is a new policy change, and so a new decision.

Pure stdlib, networkless: it judges only the evidence the trusted workflow recorded.
"""
from __future__ import annotations

import re

import scoped_grant

SCHEMA = "aeos-admitted-programme/v1"
ACTIVATIONS = ("enabled", "disabled")
ENTRY_KEYS = frozenset({"schema", "programme", "path_envelope", "activation", "decision"})
MAX_ENTRIES = 32
MAX_PATHS = 16
MAX_DECISION_CHARS = 500
MAX_PROGRAMME_EDITS = 100
#: Never reachable from an envelope: the merge control plane and this judge's own home.
EXCLUDED_PREFIXES = (".github/", "aeos/")

ADMITTED_PROGRAMME_DISABLED = "ADMITTED_PROGRAMME_DISABLED"
ADMITTED_PROGRAMME_UNAVAILABLE = "ADMITTED_PROGRAMME_UNAVAILABLE"
ADMITTED_PROGRAMME_NOT_OPEN = "ADMITTED_PROGRAMME_NOT_OPEN"
ADMITTED_PROGRAMME_NOT_OPERATOR = "ADMITTED_PROGRAMME_NOT_OPERATOR"
ADMITTED_PROGRAMME_EDITED_BY_NON_OPERATOR = "ADMITTED_PROGRAMME_EDITED_BY_NON_OPERATOR"
ADMITTED_PROGRAMME_REPOSITORY_MISMATCH = "ADMITTED_PROGRAMME_REPOSITORY_MISMATCH"
ADMITTED_PROGRAMME_PATH_OUTSIDE_ENVELOPE = "ADMITTED_PROGRAMME_PATH_OUTSIDE_ENVELOPE"
ADMITTED_PROGRAMME_NOT_REGULAR_FILE = "ADMITTED_PROGRAMME_NOT_REGULAR_FILE"
ADMITTED_PROGRAMME_STALE_CONTEXT = "ADMITTED_PROGRAMME_STALE_CONTEXT"
#: The approval collector's context for a pull request that, read fresh twice, still has the event's head and body.
CONTEXT_CURRENT = "CURRENT"

_REF = re.compile(r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)#([1-9][0-9]*)")
_SEGMENT = re.compile(r"[A-Za-z0-9_.@+-]+")


def _exact_path(path) -> bool:
    if not isinstance(path, str) or not path or path.startswith("/") or path.endswith("/"):
        return False
    parts = path.split("/")
    return all(part not in ("", ".", "..") and _SEGMENT.fullmatch(part) for part in parts)


def _key(ref):
    """``(owner/repo lower-cased, number)``: the identity GitHub gives the Issue, whatever the spelling."""
    match = _REF.fullmatch(ref) if isinstance(ref, str) else None
    return None if match is None else (match[1].lower(), int(match[2]))


def validate(entries, *, roots, excluded, in_allowlist) -> None:
    """``ValueError`` unless ``entries`` is a list of well-formed entries whose envelopes reach only ordinary
    protected members: never a root, an excluded path, the control plane or a path outside the allowlist.
    ``excluded`` is ``None`` when no exclusion list is configured: then no entry may be admitted at all."""
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        raise ValueError("admitted_programmes must be a list")
    if entries and excluded is None:
        raise ValueError("admitted_programmes needs the scoped-grant exclusion list configured")
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS or entry.get("schema") != SCHEMA:
            raise ValueError(f"each admitted programme is exactly {sorted(ENTRY_KEYS)} with schema {SCHEMA}")
        key = _key(entry["programme"])
        if key is None or key in seen:
            raise ValueError("admitted programme must be a unique owner/repo#N")
        seen.add(key)
        if entry["activation"] not in ACTIVATIONS:
            raise ValueError("admitted programme activation must be enabled or disabled")
        decision = entry["decision"]
        if not isinstance(decision, str) or not decision.strip() or len(decision) > MAX_DECISION_CHARS:
            raise ValueError("admitted programme must record its decision")
        paths = entry["path_envelope"]
        if (not isinstance(paths, list) or not 1 <= len(paths) <= MAX_PATHS
                or not all(_exact_path(p) for p in paths) or len(set(paths)) != len(paths)):
            raise ValueError("admitted programme path_envelope must list 1..16 exact, unique paths")
        for path in paths:
            if (path.lower().startswith(EXCLUDED_PREFIXES) or path in roots or path in excluded
                    or not in_allowlist(path)):
                raise ValueError(f"admitted programme path {path!r} may never be admitted")


def entry_for(entries, ref):
    """The entry for ``ref`` under GitHub's identity (enabled or not), or ``None``."""
    key = _key(ref)
    for entry in entries or ():
        if key is not None and _key(entry["programme"]) == key:
            return entry
    return None


def refusal(entry, evidence, ref, *, operators, repository, entries) -> str | None:
    """``None`` when this machine-authored carrier is admitted under ``entry``; otherwise the ONE typed reason.

    ``entries`` are the candidate's protected entries (``path`` and ``rename_from``). The machine route has
    already checked the author, actor, head-commit author and evidence repository before calling this."""
    if entry.get("activation") != "enabled":
        return ADMITTED_PROGRAMME_DISABLED
    if _key(ref) is None or _key(ref)[0] != (repository or "").strip().lower():
        return ADMITTED_PROGRAMME_REPOSITORY_MISMATCH
    pr = evidence.get("pull_request") if isinstance(evidence, dict) else None
    approval = pr.get("approval") if isinstance(pr, dict) else None
    if not isinstance(approval, dict) or approval.get("context") != CONTEXT_CURRENT:
        return ADMITTED_PROGRAMME_STALE_CONTEXT
    programme = evidence.get("programme") if isinstance(evidence, dict) else None
    if not isinstance(programme, dict) or programme.get("ref") != ref or programme.get("unavailable"):
        return ADMITTED_PROGRAMME_UNAVAILABLE
    if programme.get("state") != "open":
        return ADMITTED_PROGRAMME_NOT_OPEN
    if programme.get("author_login") not in operators or programme.get("author_type") != "User":
        return ADMITTED_PROGRAMME_NOT_OPERATOR
    editors = programme.get("editors")
    if (not isinstance(editors, list) or len(editors) > MAX_PROGRAMME_EDITS
            or any(not isinstance(e, str) for e in editors)):
        return ADMITTED_PROGRAMME_UNAVAILABLE
    if any(e not in operators for e in editors):
        return ADMITTED_PROGRAMME_EDITED_BY_NON_OPERATOR
    envelope = set(entry["path_envelope"])
    for item in entries:
        for path in (item.path, item.rename_from):
            if path is not None and path not in envelope:
                return ADMITTED_PROGRAMME_PATH_OUTSIDE_ENVELOPE
        if not scoped_grant._regular_file_entry(item):
            return ADMITTED_PROGRAMME_NOT_REGULAR_FILE
    return None
