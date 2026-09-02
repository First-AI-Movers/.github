#!/usr/bin/env python3
"""Content-addressed git reads, shared by the AEOS post-main rail.

Every module in this directory that needs to know what a commit *contains* goes
through here rather than through the working tree. A working tree is a place
bytes happen to be sitting; a blob id is a statement about which bytes they are.
That distinction is what lets a verdict be bound to the commit it is reported
against.

Nothing here executes repository content, and every git invocation is argv-only
with no shell.
"""

from __future__ import annotations

import os
import re
import subprocess

SHA_RE = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")
ZERO_SHA = "0" * 40
GIT_TIMEOUT_SECONDS = 60

MODE_SYMLINK = "120000"
MODE_GITLINK = "160000"


class GitUnavailable(Exception):
    """git itself could not answer. Never evidence about the code under test."""


class MalformedPath(Exception):
    """git reported a path that cannot be trusted as a repository-relative path."""


def run_git(
    repo_root, args: list[str], stdin: str | None = None
) -> subprocess.CompletedProcess:
    """Run one git command. argv only -- never a shell, never repository content."""
    cmd = ["git", "-C", str(repo_root), "--no-pager"] + args
    try:
        return subprocess.run(
            cmd,
            input=stdin.encode() if stdin is not None else None,
            capture_output=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitUnavailable(f"git is not installed: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitUnavailable(f"git timed out: {' '.join(args)}") from exc


def is_full_sha(sha: str | None) -> bool:
    """A full object id only.

    An abbreviated prefix resolves, which would make the commit acted on a
    function of what else happens to be in the object store rather than of what
    the event named.
    """
    return bool(sha) and bool(SHA_RE.match(sha.strip().lower()))


def commit_exists(repo_root, sha: str) -> bool:
    if not is_full_sha(sha):
        return False
    return run_git(repo_root, ["rev-parse", "--verify", "--quiet", f"{sha}^{{commit}}"]).returncode == 0


def safe_relpath(path: str) -> str:
    if not path:
        raise MalformedPath("git reported an empty path")
    if path.startswith("/") or (len(path) > 1 and path[1] == ":"):
        raise MalformedPath(f"git reported an absolute path: {path!r}")
    parts = path.split("/")
    if ".." in parts or "" in parts[:-1]:
        raise MalformedPath(f"git reported a traversing path: {path!r}")
    return path


def tree_entry(repo_root, sha: str, path: str):
    """Return ``(mode, obj_type, blob_sha)`` for ``<sha>:<path>``, or ``None``.

    ``None`` means the path is simply absent from that commit, which is a normal
    answer and never an error.
    """
    listing = run_git(repo_root, ["ls-tree", "-z", sha, "--", path])
    if listing.returncode != 0:
        detail = listing.stderr.decode("utf-8", "replace").strip() or "git ls-tree failed"
        raise GitUnavailable(f"cannot inspect the tree of {sha}: {detail}")
    record = listing.stdout.split(b"\0")[0].decode("utf-8", "replace").strip()
    if not record:
        return None
    try:
        meta, _ = record.split("\t", 1)
        mode, obj_type, blob_sha = meta.split()
    except ValueError as exc:
        raise GitUnavailable(f"unreadable tree entry for {path!r}: {exc}") from exc
    return mode, obj_type, blob_sha


def read_blob(repo_root, blob_sha: str, max_bytes: int) -> bytes:
    """Read one blob, refusing before buffering anything oversized."""
    sizing = run_git(repo_root, ["cat-file", "-s", blob_sha])
    if sizing.returncode != 0:
        raise GitUnavailable(f"cannot size object {blob_sha}")
    try:
        declared = int(sizing.stdout.decode().strip())
    except ValueError as exc:
        raise GitUnavailable(f"git reported a non-numeric size for {blob_sha}") from exc
    if declared > max_bytes:
        raise ValueError(f"object {blob_sha} is {declared} bytes, over the {max_bytes}-byte limit")
    blob = run_git(repo_root, ["cat-file", "blob", blob_sha])
    if blob.returncode != 0:
        raise GitUnavailable(f"cannot read object {blob_sha}")
    return blob.stdout


def read_file_at(repo_root, sha: str, path: str, max_bytes: int):
    """Content of ``path`` at commit ``sha``, or ``None`` if it is not there.

    Raises ``ValueError`` when the path exists but is not a regular file or is
    oversized -- states a caller must decide about explicitly rather than
    receive as an indistinguishable ``None``.
    """
    entry = tree_entry(repo_root, sha, safe_relpath(path))
    if entry is None:
        return None
    mode, obj_type, blob_sha = entry
    if obj_type != "blob":
        raise ValueError(f"{path} is a {obj_type}, not a file")
    if mode == MODE_SYMLINK:
        raise ValueError(f"{path} is a symlink, not a regular file")
    if mode == MODE_GITLINK:
        raise ValueError(f"{path} is a submodule reference, not a file")
    return read_blob(repo_root, blob_sha, max_bytes)


def changed_paths(repo_root, sha: str) -> list[str]:
    """Paths a commit touched, relative to its first parent (or the root commit)."""
    proc = run_git(
        repo_root,
        ["diff-tree", "--no-commit-id", "--name-only", "-r", "--root", "-z",
         "--no-ext-diff", "--no-textconv", sha],
    )
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip() or "git diff-tree failed"
        raise GitUnavailable(f"cannot read the changed paths of {sha}: {detail}")
    out = []
    for raw in proc.stdout.split(b"\0"):
        if raw:
            out.append(safe_relpath(os.fsdecode(raw)))
    return out
