#!/usr/bin/env python3
"""scoped_grant.py -- the organization judge for one SCOPED_MACHINE_GRANT (agent-toolkit #3052 Class B).

The operator pre-authorized a CLASS of grant in their own words (agent-toolkit #3752 comment
5871353356): an exact list of Agent Toolkit derivation-protected files, tied to admitted work, bounded
to at most seven days, recorded with an activation receipt that cites the directive, the activating
session and the time, and still delivered through the ordinary merge rail. Such a grant is activated by
the session that needs it and is never put to the operator. This module is the one place the gate
decides whether a machine-authored pull request may lean on such an activation.

What a grant is, and is not
---------------------------
A grant only NARROWS the compiler programme's envelope (``machine_route.authority_compiler``) to the
exact files its record names. It never widens anything: the programme Issue's own conjuncts (open,
operator-authored, operator-only edits, ACTIVE, unexpired) are checked by ``derivation_policy`` first,
and a pull request that carries a grant marker is judged ONLY against the grant from then on.

Every premise is a fact GitHub already holds, collected by the trusted workflow
(:func:`collect`) and judged here without a network (:func:`judge`):

* **The record.** One Issue authored by the pinned machine principal, numbered in exactly one
  machine edit inside the activation window, whose body is byte-identical to the version the pull
  request names (``scoped-machine-grant: owner/repo#N@sha256:<body>``). It carries one
  ``standing-authority/v2`` block naming itself, and one activation receipt.
* **The directive.** The operator's own, unedited comment, identified by id and pinned by the
  SHA-256 of its body in this trusted policy. A stand-in body refuses.
* **Admission.** The ONE Issue the receipt serves is a canonized root under the same rules the
  incumbent reader applies (agent-toolkit ``standing_ceiling.CanonizedRootVerifier``): open, no
  ceiling block of its own, operator-authored, complete operator-only edit history, the admission
  label present and last applied by the current body's origin at or after the last edit, and no
  sub-issue parent. An operator-authored note that was never admitted is NOT admitted.
* **Ownership.** The receipt's ``activated_by`` is the node named by the live #5731 generation claim
  of the served generation, whose ref still points at the receipt's ``claim_commit``. That commit is
  authored by the machine principal, signed by GitHub, names exactly that node and generation, holds
  the claim, and predates the activation. A free-text session name is not ownership.
* **Time.** The activation time is GitHub's own creation time of the record, never a clock the
  activator chose. A record from the future, a receipt whose time differs from the record's creation,
  a TTL above the class or binding ceiling, or an expired grant refuses.

Every route out returns one code from the closed vocabulary below. The binding in trusted policy
(``machine_route.scoped_grant``) carries ``activation``: ``disabled`` refuses every grant-marked pull
request, so landing this code changes no admission until that switch is turned in this repository.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import re

BINDING_SCHEMA = "aeos-scoped-grant-consumer/v1"
RECEIPT_SCHEMA = "scoped-machine-grant-activation/v2"
BLOCK_SCHEMA = "standing-authority/v2"
SCOPE = "repository-code"
ACTIVATIONS = ("enabled", "disabled")

MAX_PATHS = 64
"""The most exact files one record may name."""
ACTIVATION_WINDOW_SECONDS = 3600
"""The record is created as an inert placeholder and numbered in exactly one edit inside this window."""
CLASS_MAX_TTL_SECONDS = 7 * 24 * 3600
"""The directive's own bound: ``not_after`` is at most seven days after activation."""
MAX_RECORD_EDITS = 100
MAX_EVIDENCE_AGE_SECONDS = 300
"""How old the collected facts may be when judged (``comment_operand.MAX_AGE_SECONDS``): the workflow collects
them seconds before the gate runs, so anything older, or from the future, is not a reading of now."""
GITHUB_SIGNER = "web-flow"
"""The committer GitHub records for a commit it created and signed through its API."""

ACTIVATOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{2,127}\Z")
REF = re.compile(r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)#([1-9][0-9]*)\Z")
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_DIGEST = re.compile(r"(?:intent-v1:)?sha256:[0-9a-f]{64}\Z")
_MARKER = re.compile(r"<!--\s*scoped-machine-grant:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)#([1-9][0-9]{0,9})"
                     r"@sha256:([0-9a-f]{64})\s*-->")
"""At most ten digits: GitHub's GraphQL ``Int`` carries no larger Issue number, and a longer run is never converted."""
_MARKER_TOKEN = "scoped-machine-grant:"
_BLOCK = re.compile(r"^```standing-authority[ \t]*\n(.*?)\n```[ \t]*(?:\n|$)", re.M | re.S)
_CLAIM_PREFIX = "refs/aeos-claims/"
_YAML_FENCE = re.compile(r"```ya?ml[ \t]*\r?\n(.*?)```", re.DOTALL | re.IGNORECASE)
"""agent-toolkit ``agent_relay.commission._YAML_BLOCK``: the only place its intent projection can move bytes."""

EXCLUDED_PREFIXES = (".github/", "aeos/")
"""Lower-case path prefixes no grant may name: the merge control plane and this judge's own home."""

RECEIPT_KEYS = frozenset({"schema", "programme", "directive_comment_id", "serves", "generation", "claim_ref",
                          "claim_commit", "scope", "activated_by", "activated_at"})
BINDING_KEYS = frozenset({"schema", "programme", "directive_comment_id", "directive_body_sha256",
                          "max_ttl_seconds", "excluded_paths", "admission_label", "activation"})

# -- the closed vocabulary --------------------------------------------------------------------------
SCOPED_GRANT_DISABLED = "MACHINE_ROUTE_SCOPED_GRANT_DISABLED"
SCOPED_GRANT_UNBOUND = "MACHINE_ROUTE_SCOPED_GRANT_UNBOUND"
SCOPED_GRANT_UNAVAILABLE = "MACHINE_ROUTE_SCOPED_GRANT_UNAVAILABLE"
SCOPED_GRANT_MARKER_INVALID = "MACHINE_ROUTE_SCOPED_GRANT_MARKER_INVALID"
SCOPED_GRANT_RECORD_INVALID = "MACHINE_ROUTE_SCOPED_GRANT_RECORD_INVALID"
SCOPED_GRANT_RECORD_NOT_MACHINE = "MACHINE_ROUTE_SCOPED_GRANT_RECORD_NOT_MACHINE"
SCOPED_GRANT_INACTIVE = "MACHINE_ROUTE_SCOPED_GRANT_INACTIVE"
SCOPED_GRANT_DIRECTIVE_INVALID = "MACHINE_ROUTE_SCOPED_GRANT_DIRECTIVE_INVALID"
SCOPED_GRANT_ACTIVATION_TIME_INVALID = "MACHINE_ROUTE_SCOPED_GRANT_ACTIVATION_TIME_INVALID"
SCOPED_GRANT_TTL_INVALID = "MACHINE_ROUTE_SCOPED_GRANT_TTL_INVALID"
SCOPED_GRANT_EXPIRED = "MACHINE_ROUTE_SCOPED_GRANT_EXPIRED"
SCOPED_GRANT_ENVELOPE_INVALID = "MACHINE_ROUTE_SCOPED_GRANT_ENVELOPE_INVALID"
SCOPED_GRANT_ADMISSION_UNPROVEN = "MACHINE_ROUTE_SCOPED_GRANT_ADMISSION_UNPROVEN"
SCOPED_GRANT_GENERATION_UNBOUND = "MACHINE_ROUTE_SCOPED_GRANT_GENERATION_UNBOUND"
SCOPED_GRANT_NOT_REGULAR_FILE = "MACHINE_ROUTE_SCOPED_GRANT_NOT_A_REGULAR_FILE"
SCOPED_GRANT_SOURCE_MOVED = "MACHINE_ROUTE_SCOPED_GRANT_SOURCE_MOVED"
SCOPED_GRANT_EVIDENCE_NOT_CURRENT = "MACHINE_ROUTE_SCOPED_GRANT_EVIDENCE_NOT_CURRENT"
SCOPED_GRANT_PROGRAMME_MISMATCH = "MACHINE_ROUTE_SCOPED_GRANT_PROGRAMME_MISMATCH"
SCOPED_GRANT_OWNER_UNPROVEN = "MACHINE_ROUTE_SCOPED_GRANT_OWNER_UNPROVEN"
PATH_OUTSIDE_ENVELOPE = "MACHINE_ROUTE_PATH_OUTSIDE_ENVELOPE"
REPOSITORY_MISMATCH = "MACHINE_ROUTE_REPOSITORY_MISMATCH"

MARKER_ABSENT = "absent"

REGULAR_MODES = frozenset({"100644", "100755"})
"""The only git modes a granted path may have on either side: a regular or an executable file."""
ABSENT_MODE = "000000"
ABSENT_IMAGE = "absent"
"""``derivation_policy.ABSENT``: the image value of a side that does not exist (an add's pre, a delete's post)."""
MARKER_MALFORMED = "malformed"


# -- pure helpers shared with the activator and publisher -------------------------------------------
def _exact_path(path) -> bool:
    """A repository-relative exact file: no leading slash, no trailing slash, no empty/dot segment."""
    return (isinstance(path, str) and bool(path) and not path.startswith("/") and not path.endswith("/")
            and "\\" not in path and all(part not in ("", ".", "..") for part in path.split("/")))


def claim_ref(generation: str) -> str:
    """The #5731 claim ref of one generation, exactly as agent-toolkit ``write_branch`` derives it.
    Raises ``ValueError`` for anything that is not ``owner/repo#N@<digest>``."""
    if not isinstance(generation, str) or "@" not in generation or "#" not in generation:
        raise ValueError("generation must be owner/repo#N@<digest>")
    head, digest = generation.split("@", 1)
    match = REF.fullmatch(head)
    if match is None or not _DIGEST.fullmatch(digest):
        raise ValueError("generation must be owner/repo#N@<digest>")
    if digest.startswith("intent-v1:"):
        hexed = hashlib.sha256(digest.encode("ascii")).hexdigest()
    else:
        hexed = digest[len("sha256:"):]
    return f"{_CLAIM_PREFIX}{match[2]}/{hexed[:12]}"


def current_generation(serves: str, body: str, version: str):
    """The served Issue's CURRENT generation key under ``version``, exactly as agent-toolkit's dispatcher mints
    it: ``auto_execute_queue.generation_key(repo, issue, digest_for_version(body, version))``, i.e.
    ``<repo>#<issue>@sha256:<hex>`` (``v0``, the exact body) or ``@intent-v1:sha256:<hex>`` (the body's
    intent projection), hashed over UTF-8 with ``surrogatepass``.

    That projection removes placement lines only inside a fenced YAML block carrying ``commission_version``
    and is the identity on every other body. An admitted canonized root is plain prose, so this judge
    accepts an ``intent-v1`` generation only where the projection is provably the identity (no fenced YAML
    block at all) and returns ``None`` otherwise: it never re-implements the projection. ``None`` too for an
    unknown version or a malformed ``serves``."""
    if not isinstance(serves, str) or not REF.fullmatch(serves) or not isinstance(body, str):
        return None
    raw = body.encode("utf-8", "surrogatepass")
    if version == "v0":
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    elif version == "intent-v1":
        if _YAML_FENCE.search(body) is not None:
            return None
        digest = "intent-v1:sha256:" + hashlib.sha256(raw).hexdigest()
    else:
        return None
    return f"{serves}@{digest}"


def _fence(body: str, tag: str):
    if not isinstance(body, str):
        return None
    found = re.findall(r"^```" + re.escape(tag) + r"[ \t]*\n(.*?)\n```[ \t]*$", body, re.M | re.S)
    if len(found) != 1:
        return None
    try:
        value = json.loads(found[0], object_pairs_hook=_unique_pairs)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def receipt_of(body: str):
    """The one activation receipt on a record body, or ``None``."""
    return _fence(body, RECEIPT_SCHEMA)


def _block_of(body: str):
    """The one ``standing-authority/v2`` block on a record body, read with the keys a grant needs."""
    if not isinstance(body, str):
        return None
    matches = list(_BLOCK.finditer(body))
    if len(matches) != 1:
        return None
    try:
        block = json.loads(matches[0][1], object_pairs_hook=_unique_pairs)
    except ValueError:
        return None
    if (not isinstance(block, dict) or set(block) != {"schema", "state", "repository", "issue", "not_after",
                                                         "path_envelope"}
            or block["schema"] != BLOCK_SCHEMA or not isinstance(block["repository"], str)
            or type(block["issue"]) is not int or not isinstance(block["state"], str)
            or not isinstance(block["not_after"], str) or not isinstance(block["path_envelope"], list)):
        return None
    return block


def marker_state(body):
    """``MARKER_ABSENT``, ``MARKER_MALFORMED``, or ``(repository, number, body_sha256)``."""
    if not isinstance(body, str) or _MARKER_TOKEN not in body:
        return MARKER_ABSENT
    markers = _MARKER.findall(body)
    if len(markers) != 1 or body.count(_MARKER_TOKEN) != 1:
        return MARKER_MALFORMED
    repository, number, digest = markers[0]
    return repository, int(number), digest


def _parse_stamp(value):
    if not isinstance(value, str) or not STAMP.fullmatch(value):
        return None
    try:
        return _dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc).timestamp()
    except ValueError:
        return None


def _iso(value):
    """Any GitHub ISO-8601 instant as epoch seconds, or ``None``."""
    if not isinstance(value, str):
        return None
    try:
        stamp = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return stamp.timestamp() if stamp.tzinfo is not None else None


def _machine_login(author, machine_logins) -> bool:
    """A GraphQL ``Bot`` author (login without the ``[bot]`` suffix) or a REST bot login is the machine."""
    if not isinstance(author, dict) or not isinstance(author.get("login"), str):
        return False
    login, kind = author["login"], author.get("__typename", author.get("type"))
    if kind != "Bot":
        return False
    return login in machine_logins or f"{login}[bot]" in machine_logins


# -- trusted-policy binding ---------------------------------------------------------------------------
def validate_binding(binding, *, compiler) -> None:
    """Validate ``machine_route.scoped_grant``. Raises ``ValueError``; the policy loader maps it onto
    ``GATE_CONFIG_INVALID``."""
    if not isinstance(binding, dict) or set(binding) != BINDING_KEYS or binding["schema"] != BINDING_SCHEMA:
        raise ValueError("scoped_grant binding shape")
    if not isinstance(compiler, dict) or binding["programme"] != compiler.get("programme"):
        raise ValueError("scoped_grant binds only the authority-compiler programme")
    if not isinstance(binding["programme"], str) or not REF.fullmatch(binding["programme"]):
        raise ValueError("scoped_grant programme ref")
    if type(binding["directive_comment_id"]) is not int or binding["directive_comment_id"] <= 0:
        raise ValueError("scoped_grant directive_comment_id")
    if not isinstance(binding["directive_body_sha256"], str) or not SHA64.fullmatch(binding["directive_body_sha256"]):
        raise ValueError("scoped_grant directive_body_sha256")
    if (type(binding["max_ttl_seconds"]) is not int
            or not 0 < binding["max_ttl_seconds"] <= CLASS_MAX_TTL_SECONDS):
        raise ValueError("scoped_grant max_ttl_seconds exceeds the directive's seven days")
    excluded = binding["excluded_paths"]
    if (not isinstance(excluded, list) or len(set(excluded)) != len(excluded)
            or not all(_exact_path(p) for p in excluded)):
        raise ValueError("scoped_grant excluded_paths")
    if (not isinstance(binding["admission_label"], str) or not binding["admission_label"]
            or len(binding["admission_label"]) > 100):
        raise ValueError("scoped_grant admission_label")
    if binding["activation"] not in ACTIVATIONS:
        raise ValueError("scoped_grant activation")


# -- the trusted workflow's collector ----------------------------------------------------------------
ISSUE_QUERY = '''query($o:String!,$n:String!,$i:Int!){repository(owner:$o,name:$n){issue(number:$i){
number repository{nameWithOwner} body state createdAt lastEditedAt
author{login __typename} editor{login} parent{number}
labels(first:100){nodes{id name} pageInfo{hasNextPage}}
userContentEdits(first:100){totalCount pageInfo{hasNextPage} nodes{editedAt deletedAt editor{login __typename}}}
timelineItems(last:50,itemTypes:[LABELED_EVENT]){pageInfo{hasPreviousPage}
nodes{... on LabeledEvent{actor{login __typename} label{id name} createdAt}}}}}}'''

DIRECTIVE_QUERY = '''query($id:ID!){node(id:$id){... on IssueComment{databaseId body createdAt lastEditedAt
author{login __typename} issue{number repository{nameWithOwner}}
userContentEdits(first:1){totalCount}}}}'''


def _graphql_issue(api, repository: str, number: int):
    owner, name = repository.split("/", 1)
    response = api("graphql", "-f", "query=" + ISSUE_QUERY, "-f", "o=" + owner, "-f", "n=" + name,
                   "-F", "i=" + str(number))
    if not isinstance(response, dict) or response.get("errors"):
        raise ValueError("issue unavailable")
    node = response["data"]["repository"]["issue"]
    if not isinstance(node, dict):
        raise ValueError("issue unavailable")
    return node


def _read(binding, api, repository: str, number: int):
    """One complete reading of every source the verdict rests on, exactly as the judge will receive it."""
    record = _graphql_issue(api, repository, number)
    programme_repo = binding["programme"].split("#", 1)[0]
    comment = api(f"repos/{programme_repo}/issues/comments/{binding['directive_comment_id']}")
    if not isinstance(comment, dict) or not isinstance(comment.get("node_id"), str):
        raise ValueError("directive unavailable")
    directive = api("graphql", "-f", "query=" + DIRECTIVE_QUERY, "-f", "id=" + comment["node_id"])
    if not isinstance(directive, dict) or directive.get("errors"):
        raise ValueError("directive unavailable")
    directive = dict(directive["data"]["node"], issue_url=comment.get("issue_url"), rest_id=comment.get("id"),
                     node_id=comment["node_id"])
    receipt = receipt_of(record.get("body"))
    served = claim = commit = None
    if isinstance(receipt, dict):
        match = REF.fullmatch(receipt.get("serves") or "") if isinstance(receipt.get("serves"), str) else None
        if match is not None and match[1].lower() == repository.lower():
            try:
                served = {"label": binding["admission_label"],
                          "node": _graphql_issue(api, match[1], int(match[2]))}
            except (KeyError, TypeError, ValueError):
                served = None
        try:
            ref = claim_ref(receipt.get("generation"))
        except ValueError:
            ref = None
        if ref is not None:
            claim = _claim_of(api(f"repos/{repository}/git/ref/{ref[len('refs/'):]}"))
            if claim is not None and isinstance(claim["sha"], str) and SHA40.fullmatch(claim["sha"]):
                raw = api(f"repos/{repository}/commits/{claim['sha']}")
                if isinstance(raw, dict):
                    inner = raw.get("commit") or {}
                    commit = {"sha": raw.get("sha"),
                              "author": raw.get("author"), "committer": raw.get("committer"),
                              "message": inner.get("message"),
                              "committed_at": (inner.get("committer") or {}).get("date"),
                              "verified": (inner.get("verification") or {}).get("verified")}
    return {"record": record, "directive": directive, "served": served, "claim": claim, "commit": commit}


def collect(binding, pr_body, api, observed_at):
    """Project authenticated GitHub facts for the one grant a pull request names; never read a grant from
    the candidate. ``api(path, *args)`` is the workflow's read-only ``gh api`` caller.

    A pull request with no marker yields ``{"marker": None}``. A record or directive that cannot be read is
    ``{"unavailable": ...}``: unreadable, never "none". An unreadable served Issue or claim is recorded as
    ``None`` and refuses at the judge.

    Every source is read twice, the second reading starting after the first has ended, and the two COMPLETE
    readings must be equal: every field the collector reads, edit histories included, for the record, the
    directive, the served Issue, the claim ref and its commit. Any difference is ``SOURCE_MOVED``, so a
    source edited (even edited and restored within one timestamp second), an admission revoked, or a claim
    superseded while the facts were being collected can never stand behind a pull request."""
    try:
        state = marker_state(pr_body)
        if state == MARKER_ABSENT:
            return {"observed_at": observed_at, "marker": None}
        if state == MARKER_MALFORMED:
            return {"observed_at": observed_at, "unavailable": SCOPED_GRANT_MARKER_INVALID}
        repository, number, digest = state
        reading = _read(binding, api, repository, number)
        if _read(binding, api, repository, number) != reading:
            return {"observed_at": observed_at, "unavailable": SCOPED_GRANT_SOURCE_MOVED}
        return {"observed_at": observed_at, "marker": {"repository": repository, "number": number,
                                                       "body_sha256": digest}, **reading}
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return {"observed_at": observed_at, "unavailable": SCOPED_GRANT_UNAVAILABLE}


def _claim_of(got):
    """The claim ref's identity as read (``ref``, target ``sha`` and ``type``), or ``None`` when absent."""
    if not isinstance(got, dict):
        return None
    target = got.get("object") or {}
    return {"ref": got.get("ref"), "sha": target.get("sha"), "type": target.get("type")}


# -- admission (the incumbent canonized-root rules) ---------------------------------------------------
def _admitted(served, ref, policy, now) -> bool:
    """Whether the served Issue is an admitted canonized root at ``now``. Never looser than agent-toolkit's
    ``CanonizedRootVerifier``; additionally a deleted edit record or a sub-issue parent refuses."""
    try:
        node, label = served["node"], served["label"]
        match = REF.fullmatch(ref)
        if match is None or not isinstance(label, str) or not label:
            return False
        if (node["repository"]["nameWithOwner"].lower() != match[1].lower() or type(node["number"]) is not int
                or node["number"] != int(match[2])):
            return False
        if node.get("parent") is not None or node["state"] != "OPEN":
            return False
        body = node["body"]
        if not isinstance(body, str) or "```standing-authority" in body or _BLOCK.search(body) is not None:
            return False
        operators = policy.operator_principals
        author = node["author"]
        if author.get("__typename") != "User" or author.get("login") not in operators:
            return False
        edits = node["userContentEdits"]
        page = edits.get("pageInfo")
        nodes = edits["nodes"]
        if (type(edits["totalCount"]) is not int or not isinstance(nodes, list) or not isinstance(page, dict)
                or page.get("hasNextPage") is not False or edits["totalCount"] != len(nodes)
                or len(nodes) > MAX_RECORD_EDITS):
            return False
        for item in nodes:
            editor = item.get("editor") if isinstance(item, dict) else None
            if (not isinstance(editor, dict) or editor.get("login") not in operators
                    or item.get("deletedAt") is not None):
                return False
        labels = node["labels"]
        present = [n for n in labels["nodes"] if isinstance(n, dict) and n.get("name") == label]
        if not present:
            return False
        label_id = present[0].get("id")
        events = [n for n in node["timelineItems"]["nodes"] if isinstance(n, dict)
                  and isinstance(n.get("label"), dict) and label_id is not None and n["label"].get("id") == label_id]
        stamps = [n.get("createdAt") for n in events]
        if not events or not all(isinstance(s, str) for s in stamps) or stamps.count(max(stamps)) != 1:
            return False
        latest = events[stamps.index(max(stamps))]
        actor = latest.get("actor")
        actor = actor.get("login") if isinstance(actor, dict) and isinstance(actor.get("login"), str) else None
        editor = node.get("editor")
        origin = (author["login"] if node.get("lastEditedAt") is None
                  else (editor.get("login") if isinstance(editor, dict) else None))
        if origin is None or origin not in operators or actor != origin:
            return False
        activated = _iso(max(stamps))
        if activated is None:
            return False
        if node.get("lastEditedAt") is not None:
            edited = _iso(node["lastEditedAt"])
            if edited is None or activated < edited:
                return False
        return activated <= now
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        return False


def _admitted_at(served):
    """The served Issue's latest admission-label time, for the activation-order check."""
    try:
        label = served["label"]
        present = [n for n in served["node"]["labels"]["nodes"] if isinstance(n, dict) and n.get("name") == label]
        label_id = present[0].get("id")
        stamps = [n.get("createdAt") for n in served["node"]["timelineItems"]["nodes"]
                  if isinstance(n, dict) and isinstance(n.get("label"), dict) and n["label"].get("id") == label_id]
        return _iso(max(stamps))
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        return None


# -- ownership (the live #5731 claim) -----------------------------------------------------------------
def _claim_lines(message, key):
    if not isinstance(message, str):
        return None
    prefix = key + "="
    return [line.strip()[len(prefix):] for line in message.splitlines() if line.strip().startswith(prefix)]


def _owned(facts, receipt, machine_logins, activated) -> bool:
    claim, commit = facts.get("claim"), facts.get("commit")
    if not isinstance(claim, dict) or not isinstance(commit, dict):
        return False
    if (claim.get("ref") != receipt["claim_ref"] or claim.get("type") != "commit"
            or claim.get("sha") != receipt["claim_commit"] or commit.get("sha") != receipt["claim_commit"]):
        return False
    author, committer = commit.get("author"), commit.get("committer")
    if (not isinstance(author, dict) or not isinstance(author.get("login"), str)
            or author.get("login") not in machine_logins or author.get("type") != "Bot"):
        return False
    if not isinstance(committer, dict) or committer.get("login") != GITHUB_SIGNER or commit.get("verified") is not True:
        return False
    nodes = _claim_lines(commit.get("message"), "node")
    generations = _claim_lines(commit.get("message"), "generation")
    states = _claim_lines(commit.get("message"), "state")
    if nodes != [receipt["activated_by"]] or generations != [receipt["generation"]]:
        return False
    if states is None or len(states) > 1 or (states and states[0] != "HELD"):
        return False
    committed = _iso(commit.get("committed_at"))
    return committed is not None and committed <= activated


# -- the judge ------------------------------------------------------------------------------------------
def _receipt_valid(receipt, binding, repository, policy, machine_logins) -> bool:
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_KEYS:
        return False
    if (receipt["schema"] != RECEIPT_SCHEMA or receipt["programme"] != binding["programme"]
            or receipt["directive_comment_id"] != binding["directive_comment_id"] or receipt["scope"] != SCOPE):
        return False
    serves = receipt["serves"]
    match = REF.fullmatch(serves) if isinstance(serves, str) else None
    if match is None or match[1].lower() != repository.lower() or serves.lower() == binding["programme"].lower():
        return False
    generation = receipt["generation"]
    if not isinstance(generation, str) or not generation.startswith(serves + "@"):
        return False
    try:
        if claim_ref(generation) != receipt["claim_ref"]:
            return False
    except ValueError:
        return False
    if not isinstance(receipt["claim_commit"], str) or not SHA40.fullmatch(receipt["claim_commit"]):
        return False
    activator = receipt["activated_by"]
    if (not isinstance(activator, str) or not ACTIVATOR.fullmatch(activator)
            or activator in policy.operator_principals or activator in machine_logins):
        return False
    return isinstance(receipt["activated_at"], str)


def _record_reason(record, marker, binding, repository, policy, machine_logins):
    """``(reason, block, receipt, created)``; reason ``None`` when the record is a valid activation."""
    if (record["repository"]["nameWithOwner"].lower() != marker["repository"].lower()
            or record["number"] != marker["number"]):
        return SCOPED_GRANT_RECORD_INVALID, None, None, None
    if marker["repository"].lower() != repository.lower():
        return REPOSITORY_MISMATCH, None, None, None
    if not _machine_login(record.get("author"), machine_logins):
        return SCOPED_GRANT_RECORD_NOT_MACHINE, None, None, None
    if record.get("state") != "OPEN":
        return SCOPED_GRANT_INACTIVE, None, None, None
    body = record.get("body")
    if not isinstance(body, str) or hashlib.sha256(body.encode()).hexdigest() != marker["body_sha256"]:
        return SCOPED_GRANT_RECORD_INVALID, None, None, None
    created = _parse_stamp(record.get("createdAt"))
    edits = record.get("userContentEdits") or {}
    nodes = edits.get("nodes")
    if (created is None or type(edits.get("totalCount")) is not int or not isinstance(nodes, list)
            or edits["totalCount"] != len(nodes) or len(nodes) != 1):
        return SCOPED_GRANT_RECORD_INVALID, None, None, None
    edit = nodes[0] if isinstance(nodes[0], dict) else {}
    if not _machine_login(edit.get("editor"), machine_logins):
        return SCOPED_GRANT_RECORD_NOT_MACHINE, None, None, None
    edited = _iso(edit.get("editedAt"))
    if (edit.get("deletedAt") is not None or edited is None or record.get("lastEditedAt") != edit.get("editedAt")
            or not 0 <= edited - created <= ACTIVATION_WINDOW_SECONDS):
        return SCOPED_GRANT_RECORD_INVALID, None, None, None
    block, receipt = _block_of(body), receipt_of(body)
    if block is None or block["issue"] != marker["number"] or not _receipt_valid(
            receipt, binding, repository, policy, machine_logins):
        return SCOPED_GRANT_RECORD_INVALID, None, None, None
    if block["repository"].lower() != repository.lower():
        return REPOSITORY_MISMATCH, None, None, None
    if block["state"] != "ACTIVE":
        return SCOPED_GRANT_INACTIVE, None, None, None
    return None, block, receipt, created


def _directive_valid(directive, binding, policy) -> bool:
    try:
        repo, number = binding["programme"].split("#", 1)
        author = directive["author"]
        return (directive["databaseId"] == binding["directive_comment_id"]
                and directive.get("rest_id") == binding["directive_comment_id"]
                and author.get("__typename") == "User" and author.get("login") in policy.operator_principals
                and directive["issue"]["number"] == int(number)
                and directive["issue"]["repository"]["nameWithOwner"].lower() == repo.lower()
                and isinstance(directive.get("issue_url"), str)
                and directive["issue_url"].lower().endswith(f"/repos/{repo}/issues/{number}".lower())
                and directive.get("lastEditedAt") is None
                and type(directive["userContentEdits"]["totalCount"]) is int
                and directive["userContentEdits"]["totalCount"] == 0
                and isinstance(directive["body"], str)
                and hashlib.sha256(directive["body"].encode()).hexdigest() == binding["directive_body_sha256"])
    except (KeyError, TypeError, AttributeError, ValueError):
        return False


def _regular_file_entry(entry) -> bool:
    """Both sides of a protected entry are regular files, or absent exactly where the image is absent.

    A symlink (``120000``) or gitlink (``160000``) at a granted path makes Python execute bytes that are not
    the granted file's, so it is never admitted, in either direction and whatever the status (added,
    modified, type-changed, renamed). An entry that carries no modes is never assumed regular."""
    for image, mode in ((getattr(entry, "pre_sha256", None), getattr(entry, "pre_mode", None)),
                        (getattr(entry, "post_sha256", None), getattr(entry, "post_mode", None))):
        if image == ABSENT_IMAGE:
            if mode != ABSENT_MODE:
                return False
        elif mode not in REGULAR_MODES:
            return False
    return True


def _envelope_valid(paths, binding, policy) -> bool:
    # Every member is an exact path (a string) BEFORE the list is made a set: ``[{}]`` refuses, never raises.
    if (not isinstance(paths, list) or not 1 <= len(paths) <= MAX_PATHS
            or not all(_exact_path(p) for p in paths) or len(set(paths)) != len(paths)):
        return False
    roots = set(policy.roots)
    for path in paths:
        if (path.lower().startswith(EXCLUDED_PREFIXES) or path in binding["excluded_paths"] or path in roots
                or not policy.in_allowlist(path)):
            return False
    return True


def _current(observed, now) -> bool:
    """``observed`` is a real time (never a boolean) no older than the bound and not from the future."""
    if isinstance(observed, bool) or not isinstance(observed, (int, float)):
        return False
    try:
        return 0 <= now - observed <= MAX_EVIDENCE_AGE_SECONDS
    except OverflowError:  # an integer no float can hold is no time
        return False


def judge(binding, policy, evidence, repository: str, entries, now: float):
    """``None`` when the grant the pull request names admits every protected entry; otherwise the ONE
    typed reason it does not. Networkless: it reads only the trusted workflow's evidence. It never raises:
    whatever shape a GitHub reading carries, every route out is one code from the closed vocabulary."""
    if not isinstance(binding, dict) or binding.get("activation") != "enabled":
        return SCOPED_GRANT_DISABLED
    evidence = evidence if isinstance(evidence, dict) else {}
    pr = evidence.get("pull_request")
    state = marker_state(pr.get("body", "") if isinstance(pr, dict) else "")
    if state == MARKER_MALFORMED:
        return SCOPED_GRANT_MARKER_INVALID
    facts = evidence.get("scoped_grant")
    if isinstance(facts, dict) and facts.get("unavailable") == SCOPED_GRANT_SOURCE_MOVED:
        return SCOPED_GRANT_SOURCE_MOVED
    # A collection that failed carries no ``marker``; one that found none carries ``marker: None``.
    if state == MARKER_ABSENT or not isinstance(facts, dict) or not isinstance(facts.get("marker"), dict):
        return SCOPED_GRANT_UNAVAILABLE
    if not _current(facts.get("observed_at"), now):
        return SCOPED_GRANT_EVIDENCE_NOT_CURRENT
    marker = facts["marker"]
    if (marker.get("repository"), marker.get("number"), marker.get("body_sha256")) != state:
        return SCOPED_GRANT_UNAVAILABLE  # facts collected for another grant than the one this PR names
    machine_logins = {login for login, _kind in policy.machine_principals}
    try:
        reason, block, receipt, created = _record_reason(facts["record"], marker, binding, repository, policy,
                                                          machine_logins)
    except (KeyError, TypeError, AttributeError, ValueError):  # ValueError: a body UTF-8 cannot encode
        return SCOPED_GRANT_RECORD_INVALID
    if reason is not None:
        return reason
    if not _directive_valid(facts.get("directive"), binding, policy):
        return SCOPED_GRANT_DIRECTIVE_INVALID
    # Time: the activation instant is GitHub's creation of the record, never the activator's clock.
    if _parse_stamp(receipt["activated_at"]) != created or created > now:
        return SCOPED_GRANT_ACTIVATION_TIME_INVALID
    not_after = _parse_stamp(block["not_after"])
    if not_after is None or not 0 < not_after - created <= min(binding["max_ttl_seconds"], CLASS_MAX_TTL_SECONDS):
        return SCOPED_GRANT_TTL_INVALID
    if now >= not_after:
        return SCOPED_GRANT_EXPIRED
    paths = block["path_envelope"]
    if not _envelope_valid(paths, binding, policy):
        return SCOPED_GRANT_ENVELOPE_INVALID
    for entry in entries:
        if not _regular_file_entry(entry):
            return SCOPED_GRANT_NOT_REGULAR_FILE
    allowed = set(paths)
    for entry in entries:
        for path in (entry.path, entry.rename_from):
            if path is not None and path not in allowed:
                return PATH_OUTSIDE_ENVELOPE
    served = facts.get("served")
    if not _admitted(served, receipt["serves"], policy, now):
        return SCOPED_GRANT_ADMISSION_UNPROVEN
    admitted_at = _admitted_at(served)
    if admitted_at is None or admitted_at > created:
        return SCOPED_GRANT_ADMISSION_UNPROVEN
    # The receipt (and, through ownership below, the claim) must name the served Issue's CURRENT admitted
    # generation: a still-HELD claim of an old generation cannot authorize a changed mission.
    digest = receipt["generation"].split("@", 1)[1]
    version = "intent-v1" if digest.startswith("intent-v1:") else "v0"
    if receipt["generation"] != current_generation(receipt["serves"], served["node"]["body"], version):
        return SCOPED_GRANT_GENERATION_UNBOUND
    if not _owned(facts, receipt, machine_logins, created):
        return SCOPED_GRANT_OWNER_UNPROVEN
    return None
