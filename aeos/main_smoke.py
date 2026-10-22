#!/usr/bin/env python3
"""``aeos-main-smoke`` -- post-merge deterministic smoke of an exact merged SHA.

Runs after a squash lands on the default branch and emits exactly one
machine-readable outcome:

    PASS               every check ran to completion and passed
    CODE_FAILURE       at least one check ran to completion and reported a defect,
                       and NO check was prevented from running -- the failure is
                       evidence about the code
    INFRA_UNAVAILABLE  a check could not be executed (tool missing, install
                       failure, timeout, checkout identity mismatch) -- the run
                       says NOTHING about the code and must never drive a revert
                       on its own; the same reason on the previous commit is not
                       an outage (``promote_repeated_infra``)

The classification is structural, not heuristic: each check declares what "could
not run" means for it versus what "ran and found a defect" means. A run with ANY
infrastructure failure is INFRA_UNAVAILABLE even if another check reported a
defect, because a degraded measurement is not a confirmation.

Repository-agnostic. The smoke is derived, in order, from:

    1. ``.github/aeos-smoke.json`` at the merged SHA -- the repository names its
       own commands;
    2. language defaults -- a syntax and undefined-name floor for Python, and
       ``npm test`` only where a ``test`` script actually exists;
    3. neither -- ``NO_SMOKE_DEFINED``, reported as a PASS with an explicit note.

A repository with no tests at all is a normal repository, not a broken one. What
is never acceptable is a green that quietly measured nothing, so the third case
is stated in the outcome rather than left to be inferred from an empty check list.

Every CODE_FAILURE carries a deterministic ``signature`` so the circuit breaker
can require the SAME failure twice on the SAME SHA before reverting. The
signature is built only from identifiers that are stable across two runs of the
same commit -- check id, typed reason, and sorted findings where a tool emits
structured ones. Raw process output never contributes: a timestamp or a
temporary path in a signature would make every failure look flaky, and the rail
would never fire.

Exit: 0 PASS - 1 CODE_FAILURE - 3 INFRA_UNAVAILABLE.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gitobject  # noqa: E402

# Preload what CPython would otherwise import lazily on an unhandled exception.
# Nothing should be imported after a repository command has run: the policy
# interpreter's only writable `sys.path` entry is its own checkout, and although
# the workflow makes that read-only before any command runs, an empty
# lazy-import surface should not depend on a filesystem permission holding.
for _preload in ("traceback", "linecache", "tokenize"):
    __import__(_preload)
del _preload

SCHEMA_VERSION = "1"
CHECK_CONTEXT = "aeos-main-smoke"
OUTCOMES = ("PASS", "CODE_FAILURE", "INFRA_UNAVAILABLE")
EXIT = {"PASS": 0, "CODE_FAILURE": 1, "INFRA_UNAVAILABLE": 3}

SMOKE_CONFIG_PATH = ".github/aeos-smoke.json"
MAX_CONFIG_BYTES = 64 * 1024
MAX_COMMANDS = 32
MAX_ITEMS = 200
DEFAULT_TIMEOUT_SECONDS = 600
MIN_TIMEOUT_SECONDS = 1
#: The whole smoke's time, in minutes. The workflow bounds the step that runs
#: this module by the same number, and this module stops early enough to write
#: its outcome first: a run that outgrows its budget ends typed
#: SMOKE_BUDGET_EXHAUSTED, never as a killed job with no outcome. The default is
#: the bound every smoke had before a repository could declare one.
DEFAULT_BUDGET_MINUTES = 20
#: Before the budget can be asked, the smoke reads its own inputs: identity,
#: the declaration (tree entry, size, blob), the tree listing and, for a full
#: history, two checks -- at most this many git calls, each bounded at 60 s. The
#: smallest budget leaves room for all of them inside its deadline.
PREFLIGHT_GIT_CALLS = 7
MIN_BUDGET_MINUTES = 10
MAX_BUDGET_MINUTES = 280
BUDGET_MARGIN_SECONDS = 60
#: One command may use the largest budget; the run's own budget still caps it.
MAX_TIMEOUT_SECONDS = MAX_BUDGET_MINUTES * 60
SCHEMA_VERSIONS = ("1", 1)

#: How much history the checkout holds. ``shallow`` -- the merged commit alone --
#: is the default. ``full`` is every commit the merged SHA reaches, for a
#: repository whose own checks replay recorded history: a test that reads a
#: recorded commit cannot run in a checkout that does not contain it. The
#: workflow fetches it with the job's read token and keeps no credential.
HISTORY_CHOICES = ("shallow", "full")
DEFAULT_HISTORY = "shallow"

#: A failing command's output, kept beside the outcome and never inside it. The
#: start of a stream holds the first traceback and the end holds the summary, so
#: both ends are kept and the middle is dropped.
FAILURE_OUTPUT_HEAD_CHARS = 8192
FAILURE_OUTPUT_TAIL_CHARS = 4096

#: The merge gate's credential shapes (``merge_ready_gate.SECRET_SHAPES``),
#: restated so this module imports nothing beside it. A test pins the two equal.
#: No smoke command holds a credential; this is the second lock on that door.
CREDENTIAL_SHAPES = (
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9]{22,}_[A-Za-z0-9]{50,}\b")),
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private_key_block", re.compile(r"-----BEGIN[A-Z ]{0,20} PRIVATE KEY-----")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{24,}\b")),
    ("provider_api_key", re.compile(r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9]{32,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
)
CREDENTIAL_SHAPES_COMBINED = re.compile(
    "|".join(f"(?P<{name}>{pattern.pattern})" for name, pattern in CREDENTIAL_SHAPES)
)
#: The gate only detects a private key by its header line; publishing text needs
#: the whole block gone, through its END line or, unterminated, the end of stream.
PRIVATE_KEY_BLOCK = re.compile(
    dict(CREDENTIAL_SHAPES)["private_key_block"].pattern
    + r".*?(?:-----END[A-Z ]{0,20} PRIVATE KEY-----|\Z)",
    re.DOTALL,
)

#: Directories that are vendored, generated, or virtual-environment content. A
#: syntax floor that fails on a checked-in dependency tree is reporting on
#: somebody else's code, and on this rail that would drive a revert.
EXCLUDE_DIR_NAMES = (
    ".git", ".venv", "venv", "env", ".env", ".direnv", ".tox", ".nox",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".cache", "__pycache__",
    "node_modules", "vendor", "third_party", "build", "dist", "target", "out",
    ".next", ".nuxt", ".gradle", ".m2", "htmlcov", "coverage", ".eggs",
    "site-packages", ".serverless",
)
EXCLUDE_RE = r"(^|/)(" + "|".join(re.escape(d) for d in EXCLUDE_DIR_NAMES) + r")(/|$)"

#: Ruff's "syntax errors and undefined names" selection: the subset that says
#: the code cannot work, rather than that it is styled differently from someone
#: else's preference. A default lint selection would red-light most repositories
#: on adoption day, and here that means an automatic revert.
RUFF_SELECT = "E9,F63,F7,F82"

PYTHON_MARKERS = ("pyproject.toml", "setup.py", "setup.cfg")
PYTHON_MARKER_RE = re.compile(r"^requirements[^/]*\.txt$")

# Output shapes that mean the runner, the network, or a package index failed --
# not the code. Matched case-insensitively against a failing setup step only.
INFRA_OUTPUT_RE = re.compile(
    r"could not resolve host|temporary failure in name resolution|network is unreachable|"
    r"connection reset by peer|connection timed out|read timed out|"
    r"503 server error|502 bad gateway|service unavailable|"
    r"no space left on device|cannot allocate memory|rate limit",
    re.IGNORECASE,
)


#: Credentials the runner puts in the environment of every step. A repository
#: command has no business with any of them, and this job holds none of the
#: write-scoped ones by design -- stripping them is the second lock on that door.
SENSITIVE_ENV = (
    "GH_TOKEN", "GITHUB_TOKEN",
    "ACTIONS_RUNTIME_TOKEN", "ACTIONS_RUNTIME_URL",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_CACHE_URL", "ACTIONS_RESULTS_URL",
)

#: The runner's *file commands*. Anything holding one of these paths can write a
#: step output, set an environment variable for every later step in the job, or
#: prepend to PATH. A repository command that could write `outcome=PASS` into
#: GITHUB_OUTPUT would be forging this rail's verdict, and the only thing
#: standing between that and a green would be which write happened last -- which
#: is not a security property. So the smoke never hands them over.
RUNNER_FILE_COMMAND_ENV = (
    "GITHUB_OUTPUT", "GITHUB_ENV", "GITHUB_PATH", "GITHUB_STATE", "GITHUB_STEP_SUMMARY",
)

#: Hardening that belongs to the interpreter running THIS file, and to nothing
#: else. `PYTHONSAFEPATH` exists to stop a candidate shadowing a stdlib name on
#: the trusted interpreter's `sys.path`; it has no business constraining the
#: repository's own commands, which run in the repository's own context where a
#: module executed as a script importing a sibling by name is ordinary. Leaking
#: it into them turns a healthy repository's first post-main run into a
#: `ModuleNotFoundError` that says nothing about its code -- an adoption trap
#: that is silent, organization-wide, and indistinguishable from a real defect.
POLICY_INTERPRETER_ENV = (
    "PYTHONSAFEPATH", "PYTHONDONTWRITEBYTECODE",
)

WITHHELD_ENV = frozenset(SENSITIVE_ENV + RUNNER_FILE_COMMAND_ENV + POLICY_INTERPRETER_ENV)


def command_environment(environ=None) -> dict:
    env = os.environ if environ is None else environ
    return {k: v for k, v in env.items() if k not in WITHHELD_ENV}


class Tools:
    """Injection seam for tests: process runner, PATH lookup and clock."""

    def __init__(self, run=None, which=shutil.which, clock=time.monotonic):
        self.run = run or group_run
        self.which = which
        self.clock = clock


def _check(cid, status, reason, detail, items=()):
    return {
        "id": cid,
        "status": status,
        "reason": reason,
        "detail": detail,
        "items": sorted({str(i) for i in items})[:MAX_ITEMS],
    }


def _reap(pgid) -> None:
    """Kill every process still in the command's process group.

    ``subprocess.run`` waits for the direct child only. A command that
    backgrounds a writer -- ``(sleep 2; echo ... >> ../smoke.json) &`` -- returns
    control immediately and the writer then outlives the measurement, which is
    long enough to rewrite the outcome after the trusted reader has read it.
    ``subprocess.run(timeout=)`` has the same hole: it kills the process it
    waited on and leaves the descendants running for the rest of the job.
    """
    if not pgid or pgid == os.getpgrp():
        return  # never signal the group this process is in
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, sig)
        except (ProcessLookupError, PermissionError, OSError):
            return
        time.sleep(0.05)


def group_run(argv, *, cwd=None, capture_output=False, text=False, timeout=None,
              shell=False, env=None, **_ignored):
    """``subprocess.run`` with the whole process group torn down afterwards.

    ``start_new_session`` makes the child a group leader, so its pid is the group
    id and one ``killpg`` reaches every descendant it spawned -- including the
    ones it detached from itself.
    """
    pipe = subprocess.PIPE if capture_output else None
    proc = subprocess.Popen(argv, cwd=cwd, stdout=pipe, stderr=pipe, text=text,
                            shell=shell, env=env, start_new_session=True)
    try:
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _reap(proc.pid)
            proc.communicate()
            raise
    finally:
        _reap(proc.pid)
    return subprocess.CompletedProcess(argv, proc.returncode, out, err)


def _run(tools: Tools, argv, cwd, timeout, shell=False):
    """Return ``(proc, infra_reason)``. ``infra_reason`` is set when the process
    could not be run at all, which is never evidence about the code."""
    label = argv if isinstance(argv, str) else Path(argv[0]).name
    try:
        proc = tools.run(
            argv,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=shell,
            env=command_environment(),
        )
    except FileNotFoundError:
        return None, f"TOOL_MISSING:{label}"
    except subprocess.TimeoutExpired:
        return None, f"TIMEOUT:{label}"
    except OSError as exc:
        return None, f"EXEC_ERROR:{type(exc).__name__}"
    if proc.returncode == 127:
        return proc, f"TOOL_MISSING:{label}"
    return proc, None


class Budget:
    """What is left of the smoke's declared time, asked before every process."""

    def __init__(self, deadline: float, timeout: int, clock) -> None:
        self.deadline, self.timeout, self.clock = deadline, timeout, clock

    def allow(self):
        """The time the next process may take, or None once the budget is spent."""
        remaining = self.deadline - self.clock()
        return min(self.timeout, remaining) if remaining >= MIN_TIMEOUT_SECONDS else None

    def cut(self, allowed, reason: str) -> bool:
        """Whether a timeout came from the budget rather than the command's own."""
        return allowed < self.timeout and reason.startswith("TIMEOUT:")


def _budget_spent(cid: str) -> dict:
    return _check(cid, "INFRA_UNAVAILABLE", "SMOKE_BUDGET_EXHAUSTED",
                  "the declared budget_minutes ran out here; nothing after it was measured")


def _bounded_run(tools: Tools, argv, cwd, timeout, cid: str, shell=False):
    """``_run`` under a plain timeout or a :class:`Budget`: ``(proc, infra, spent)``,
    where ``spent`` is the typed check to record once the budget has run out."""
    if not isinstance(timeout, Budget):
        return (*_run(tools, argv, cwd, timeout, shell=shell), None)
    allowed = timeout.allow()
    if allowed is None:
        return None, None, _budget_spent(cid)
    proc, infra = _run(tools, argv, cwd, allowed, shell=shell)
    if infra and timeout.cut(allowed, infra):
        return None, None, _budget_spent(cid)
    return proc, infra, None


# ---------- identity ------------------------------------------------------------

def check_identity(repo_root: Path, expected_sha: str, tools: Tools) -> dict:
    if not gitobject.is_full_sha(expected_sha):
        return _check("identity", "INFRA_UNAVAILABLE", "IDENTITY_MALFORMED",
                      "the SHA under test is not a full object id; this run cannot be attributed")
    proc, infra = _run(tools, ["git", "rev-parse", "HEAD"], repo_root, 60)
    if infra or proc.returncode != 0:
        return _check("identity", "INFRA_UNAVAILABLE", infra or "GIT_ERROR",
                      "git rev-parse HEAD failed")
    head = proc.stdout.strip()
    if head != expected_sha:
        return _check("identity", "INFRA_UNAVAILABLE", "IDENTITY_MISMATCH",
                      "the checked-out HEAD is not the SHA under test -- a checkout fault, "
                      "not code evidence")
    return _check("identity", "PASS", "PASS", f"HEAD == {expected_sha}")


# ---------- declared smoke ------------------------------------------------------

class SmokeConfigError(Exception):
    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def parse_smoke_config(raw: bytes) -> dict:
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise SmokeConfigError("SMOKE_CONFIG_INVALID", f"{SMOKE_CONFIG_PATH} is not valid JSON: {exc}")
    if not isinstance(document, dict):
        raise SmokeConfigError("SMOKE_CONFIG_INVALID", f"{SMOKE_CONFIG_PATH} must contain a JSON object")

    version = document.get("schema_version")
    if not isinstance(version, (str, int)) or isinstance(version, bool) or version not in SCHEMA_VERSIONS:
        raise SmokeConfigError(
            "SMOKE_CONFIG_INVALID",
            f"{SMOKE_CONFIG_PATH} has schema_version {version!r}; this rail understands "
            f"{SCHEMA_VERSIONS[0]!r}",
        )

    plan = {"setup": [], "commands": [], "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
            "language_floor": True, "history": DEFAULT_HISTORY,
            "budget_minutes": DEFAULT_BUDGET_MINUTES}

    budget = document.get("budget_minutes", DEFAULT_BUDGET_MINUTES)
    # A boolean is an int to isinstance, and neither True nor False is in range.
    if not isinstance(budget, int) or not (MIN_BUDGET_MINUTES <= budget <= MAX_BUDGET_MINUTES):
        raise SmokeConfigError(
            "SMOKE_CONFIG_INVALID",
            f"{SMOKE_CONFIG_PATH}: budget_minutes must be an integer between "
            f"{MIN_BUDGET_MINUTES} and {MAX_BUDGET_MINUTES}",
        )
    plan["budget_minutes"] = budget

    history = document.get("history", DEFAULT_HISTORY)
    if not isinstance(history, str) or history not in HISTORY_CHOICES:
        # Exact values only, for the language_floor reason: a misspelling read
        # as the default would quietly decide which history the checks see.
        raise SmokeConfigError(
            "SMOKE_CONFIG_INVALID",
            f"{SMOKE_CONFIG_PATH}: history must be one of {', '.join(HISTORY_CHOICES)}, "
            f"not {history!r}",
        )
    plan["history"] = history

    floor = document.get("language_floor", True)
    if not isinstance(floor, bool):
        # Not truthiness: "false" and 0 are exactly the values someone reaches
        # for when they mean False, and silently reading them as True would turn
        # a request to remove the floor into a decision nobody made.
        raise SmokeConfigError(
            "SMOKE_CONFIG_INVALID",
            f"{SMOKE_CONFIG_PATH}: language_floor must be true or false, not {floor!r}",
        )
    plan["language_floor"] = floor
    timeout = document.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not (
        MIN_TIMEOUT_SECONDS <= timeout <= MAX_TIMEOUT_SECONDS
    ):
        raise SmokeConfigError(
            "SMOKE_CONFIG_INVALID",
            f"{SMOKE_CONFIG_PATH}: timeout_seconds must be an integer between "
            f"{MIN_TIMEOUT_SECONDS} and {MAX_TIMEOUT_SECONDS}",
        )
    plan["timeout_seconds"] = timeout

    for key in ("setup", "commands"):
        entries = document.get(key, [])
        if not isinstance(entries, list):
            raise SmokeConfigError("SMOKE_CONFIG_INVALID", f"{SMOKE_CONFIG_PATH}: {key} must be a list")
        if len(entries) > MAX_COMMANDS:
            raise SmokeConfigError(
                "SMOKE_CONFIG_INVALID",
                f"{SMOKE_CONFIG_PATH}: {key} holds {len(entries)} entries, over the {MAX_COMMANDS} limit",
            )
        seen = set()
        for entry in entries:
            if not isinstance(entry, dict):
                raise SmokeConfigError("SMOKE_CONFIG_INVALID", f"{SMOKE_CONFIG_PATH}: {key} entries must be objects")
            name, run = entry.get("name"), entry.get("run")
            if not isinstance(name, str) or not name.strip() or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", name):
                raise SmokeConfigError(
                    "SMOKE_CONFIG_INVALID",
                    f"{SMOKE_CONFIG_PATH}: {key} entry name {name!r} must be 1-64 chars of "
                    "letters, digits, dot, dash or underscore",
                )
            if not isinstance(run, str) or not run.strip():
                raise SmokeConfigError(
                    "SMOKE_CONFIG_INVALID",
                    f"{SMOKE_CONFIG_PATH}: {key} entry {name!r} needs a non-empty run string",
                )
            if name in seen:
                # Duplicate names would collide in the signature, and two checks
                # that cannot be told apart cannot be compared across runs.
                raise SmokeConfigError(
                    "SMOKE_CONFIG_INVALID", f"{SMOKE_CONFIG_PATH}: duplicate {key} entry name {name!r}"
                )
            seen.add(name)
            plan[key].append({"name": name, "run": run})
    if not plan["commands"]:
        raise SmokeConfigError(
            "SMOKE_CONFIG_INVALID",
            f"{SMOKE_CONFIG_PATH} is present but declares no commands; remove the file to fall "
            "back to language defaults rather than declaring an empty smoke",
        )
    return plan


def load_smoke_config(repo_root: Path, sha: str):
    """Read the declared plan from the merged SHA. ``None`` means absent, which
    is normal."""
    try:
        raw = gitobject.read_file_at(repo_root, sha, SMOKE_CONFIG_PATH, MAX_CONFIG_BYTES)
    except gitobject.GitUnavailable as exc:
        raise SmokeConfigError("SMOKE_CONFIG_UNREADABLE", str(exc))
    except (ValueError, gitobject.MalformedPath) as exc:
        raise SmokeConfigError("SMOKE_CONFIG_INVALID", str(exc))
    if raw is None:
        return None
    return parse_smoke_config(raw)


def declared_checkout(repo_root: Path, sha: str) -> dict:
    """The history and budget the declaration at ``sha`` asks for, read before the checks.

    The workflow asks this from the shallow checkout to decide whether to fetch
    more and how long the smoke step may run. Anything but a readable
    declaration answers the defaults: an absent, unreadable or invalid
    declaration is the smoke's own finding to report, and the smoke reads it
    again itself.
    """
    defaults = {"history": DEFAULT_HISTORY, "budget_minutes": DEFAULT_BUDGET_MINUTES}
    try:
        declared = load_smoke_config(Path(repo_root), sha)
    except Exception:  # noqa: BLE001 - the smoke reports it, typed
        return defaults
    if not declared:
        return defaults
    return {"history": declared["history"], "budget_minutes": declared["budget_minutes"]}


def declared_history(repo_root: Path, sha: str) -> str:
    return declared_checkout(repo_root, sha)["history"]


def check_history(repo_root: Path, tools: Tools) -> dict:
    """A declaration asked for full history: prove the checkout holds it."""
    proc, infra = _run(tools, ["git", "rev-parse", "--is-shallow-repository"], repo_root, 60)
    if infra or proc.returncode != 0 or proc.stdout.strip() not in ("true", "false"):
        return _check("history", "INFRA_UNAVAILABLE", infra or "GIT_ERROR",
                      "git could not say whether the checkout is shallow")
    if proc.stdout.strip() == "true":
        return _check("history", "INFRA_UNAVAILABLE", "HISTORY_UNAVAILABLE",
                      "the declaration asks for full history and the checkout is shallow -- "
                      "a checkout fault, not code evidence")
    # The fetch that unshallowed this checkout held the job's token. Whatever
    # happened to that step, nothing runs while a credential route is still in
    # the checkout's own configuration.
    proc, infra = _run(tools, ["git", "config", "--local", "--name-only", "--get-regexp",
                               r"^(http\..*\.extraheader|includeif\..*)$"], repo_root, 60)
    if infra or proc.returncode not in (0, 1):
        return _check("history", "INFRA_UNAVAILABLE", infra or "GIT_ERROR",
                      "git could not list the checkout's credential configuration")
    if proc.returncode == 0:
        return _check("history", "INFRA_UNAVAILABLE", "CHECKOUT_CREDENTIAL_KEPT",
                      "the full-history fetch left a credential route in the checkout; "
                      "no repository command may run beside it")
    return _check("history", "PASS", "PASS", "the checkout holds full history and no credential")


# ---------- derived defaults ----------------------------------------------------

def tracked_paths(repo_root: Path, sha: str) -> list[str]:
    proc = gitobject.run_git(repo_root, ["ls-tree", "-r", "--name-only", "-z", sha])
    if proc.returncode != 0:
        raise gitobject.GitUnavailable(f"cannot list the tree of {sha}")
    return [p for p in proc.stdout.decode("utf-8", "replace").split("\0") if p]


def _is_excluded(path: str) -> bool:
    return re.search(EXCLUDE_RE, path) is not None


FLOOR_COMPILE_ID = "floor:compile"
FLOOR_RUFF_ID = "floor:ruff"


def python_floor(paths) -> dict | None:
    """The Python syntax and undefined-name floor, or ``None`` if not applicable.

    Its check ids carry a ``floor:`` prefix, which a declared command name can
    never collide with -- declared names are restricted to letters, digits, dot,
    dash and underscore, so the colon is unavailable to them. The floor and a
    repository's own commands therefore always coexist without either having to
    know about the other.
    """
    targets = sorted(p for p in paths if p.endswith(".py"))
    has_python = bool(targets) or any(
        os.path.basename(p) in PYTHON_MARKERS or PYTHON_MARKER_RE.match(os.path.basename(p))
        for p in paths
    )
    if not has_python:
        return None
    return {
        "targets": targets,
        "setup": [{
            "name": "install-ruff",
            "run": "python3 -m pip install --quiet --disable-pip-version-check ruff",
            # Best effort. compileall needs no installation, so a package-index
            # outage must not stop the syntax floor from running and being
            # recorded. If ruff never arrives, `check_ruff` says so itself and
            # the run is INFRA_UNAVAILABLE on that basis -- one reason, from the
            # check that actually could not run.
            "best_effort": True,
        }],
        "commands": [
            {"name": FLOOR_COMPILE_ID, "run": "__compile__", "builtin": True},
            {"name": FLOOR_RUFF_ID, "run": "__ruff__", "builtin": True},
        ],
    }


def node_default(repo_root: Path, sha: str, paths) -> dict | None:
    """`npm test`, and only where a `test` script actually exists."""
    if "package.json" not in paths:
        return None
    try:
        raw = gitobject.read_file_at(repo_root, sha, "package.json", MAX_CONFIG_BYTES * 8)
        manifest = json.loads(raw.decode("utf-8")) if raw else {}
    except Exception:
        manifest = {}
    scripts = manifest.get("scripts") if isinstance(manifest, dict) else None
    if not (isinstance(scripts, dict) and isinstance(scripts.get("test"), str)
            and scripts["test"].strip()):
        return None
    install = "npm ci" if "package-lock.json" in paths else "npm install"
    return {
        "setup": [{"name": "install-node-deps", "run": f"{install} --no-audit --no-fund"}],
        "commands": [{"name": "npm-test", "run": "npm test"}],
    }


def build_plan(repo_root: Path, sha: str, tools: Tools, declared) -> dict:
    """Combine the language floor with whatever the repository declares.

    The floor runs *alongside* a declaration rather than being replaced by it.
    A declaration used to substitute for the derived default entirely, so an
    adopter who declared a smoke silently lost the syntax floor unless they
    happened to re-declare it -- ending up with less checking than doing nothing,
    while believing they had added a smoke. Removing the floor is now something
    an adopter has to ask for, in a field named for what it does.
    """
    paths = [p for p in tracked_paths(repo_root, sha) if not _is_excluded(p)]
    floor = python_floor(paths)
    setup: list[dict] = []
    commands: list[dict] = []
    parts: list[str] = []

    wants_floor = True if declared is None else declared.get("language_floor", True)
    if floor and wants_floor:
        setup += floor["setup"]
        commands += floor["commands"]
        parts.append("floor:python")

    if declared is not None:
        setup += declared["setup"]
        commands += declared["commands"]
        parts.append("declared")
        timeout = declared["timeout_seconds"]
        budget = declared["budget_minutes"]
    else:
        node = node_default(repo_root, sha, paths)
        if node:
            setup += node["setup"]
            commands += node["commands"]
            parts.append("derived:node")
        timeout = DEFAULT_TIMEOUT_SECONDS
        budget = DEFAULT_BUDGET_MINUTES

    return {
        "setup": setup,
        "commands": commands,
        "timeout_seconds": timeout,
        "budget_minutes": budget,
        "python_targets": floor["targets"] if floor else [],
        "source": "+".join(parts) if parts else "none",
    }


# ---------- built-in checks -----------------------------------------------------

_COMPILE_ERROR_RE = re.compile(r"\*\*\* Error compiling '(?P<path>[^']+)'")
_RUFF_ITEM_RE = re.compile(r"^(?P<path>[^:]+):(?P<line>\d+):\d+:\s+(?P<code>[A-Z]+\d+)")


ARGV_CHUNK = 400


def _chunks(items, size=ARGV_CHUNK):
    for start in range(0, len(items), size):
        yield items[start:start + size]


def check_compile(repo_root: Path, tools: Tools, timeout, targets=None) -> dict:
    # Note this runs through `_run`, so it inherits the repository command
    # environment -- without PYTHONDONTWRITEBYTECODE, which would otherwise stop
    # the one check whose entire job is to produce bytecode.
    """Parse every tracked Python file at the SHA.

    The file list is passed explicitly rather than walking the working tree: a
    `setup` step can generate a whole dependency tree into the checkout, and a
    syntax floor that fails on generated or untracked content is reporting on
    something the commit did not contain -- which on this rail would drive a
    revert.
    """
    targets = list(targets or [])
    if not targets:
        return _check(FLOOR_COMPILE_ID, "PASS", "PASS", "no tracked Python files")
    items, failed = set(), False
    for batch in _chunks(targets):
        argv = [sys.executable or "python3", "-m", "compileall", "-q", *batch]
        proc, infra, spent = _bounded_run(tools, argv, repo_root, timeout, FLOOR_COMPILE_ID)
        if spent:
            return spent
        if infra:
            return _check(FLOOR_COMPILE_ID, "INFRA_UNAVAILABLE", infra, "compileall could not run")
        if proc.returncode != 0:
            failed = True
            items |= {m.group("path") for m in _COMPILE_ERROR_RE.finditer(proc.stdout + proc.stderr)}
    if not failed:
        return _check(FLOOR_COMPILE_ID, "PASS", "PASS", f"{len(targets)} tracked Python file(s) parse")
    return _check(FLOOR_COMPILE_ID, "CODE_FAILURE", "COMPILE_FAILURE",
                  f"{len(items) or 'one or more'} file(s) failed to compile", items=sorted(items))


def check_ruff(repo_root: Path, tools: Tools, timeout, targets=None) -> dict:
    if not tools.which("ruff"):
        return _check(FLOOR_RUFF_ID, "INFRA_UNAVAILABLE", "TOOL_MISSING:ruff",
                      "ruff is not installed on the runner")
    targets = list(targets or [])
    if not targets:
        return _check(FLOOR_RUFF_ID, "PASS", "PASS", "no tracked Python files")
    items, failed = set(), False
    for batch in _chunks(targets):
        argv = ["ruff", "check", "--no-cache", "--force-exclude", "--select", RUFF_SELECT,
                "--output-format", "concise", *batch]
        proc, infra, spent = _bounded_run(tools, argv, repo_root, timeout, FLOOR_RUFF_ID)
        if spent:
            return spent
        if infra:
            return _check(FLOOR_RUFF_ID, "INFRA_UNAVAILABLE", infra, "ruff could not run")
        if proc.returncode == 1:
            failed = True
            items |= {f"{m.group('path')}:{m.group('line')}: {m.group('code')}"
                      for m in (_RUFF_ITEM_RE.match(ln) for ln in proc.stdout.splitlines()) if m}
        elif proc.returncode != 0:
            # Ruff exits 2 for its own usage/internal errors: the tool failing,
            # not the code failing.
            return _check(FLOOR_RUFF_ID, "INFRA_UNAVAILABLE", f"RUFF_EXIT_{proc.returncode}",
                          "ruff exited with a non-findings status")
    if not failed:
        return _check(FLOOR_RUFF_ID, "PASS", "PASS", f"no {RUFF_SELECT} findings")
    return _check(FLOOR_RUFF_ID, "CODE_FAILURE", "LINT_FAILURE", f"{len(items)} finding(s)",
                  items=sorted(items))


BUILTINS = {"__compile__": check_compile, "__ruff__": check_ruff}


# ---------- findings a failing declared command names ---------------------------

#: The kinds of finding a failing declared command can contribute, read from
#: pytest's own short test summary. ``pytest`` is a session that ran to its end,
#: so every failing test and error is listed. ``pytest-collection`` is a session
#: that collection errors interrupted before any test ran, so the list is every
#: collection error and nothing else. The breaker compares a check's findings
#: across commits only when the smoke recorded one of these kinds for it.
PYTEST_ITEMS = "pytest"
PYTEST_COLLECTION_ITEMS = "pytest-collection"
ITEM_KINDS = (PYTEST_ITEMS, PYTEST_COLLECTION_ITEMS)
MAX_ITEM_CHARS = 512

_PYTEST_SUMMARY_RE = re.compile(r"^=+ short test summary info =+$")
_PYTEST_BANNER_RE = re.compile(r"^=+ .* =+$")
_PYTEST_STOP_RE = re.compile(r"^!+ (?P<text>.*?) !+$")
_PYTEST_COLLECTION_STOP_RE = re.compile(r"^Interrupted: \d+ errors? during collection$")
_PYTEST_STATS_RE = re.compile(r"^\d+ [a-z].* in \d+(?:\.\d+)?s\b")
#: ``FAILED <node id>`` or ``ERROR <node id>``, then pytest's `` - <message>`` or
#: the end of the line. A node id is a ``.py`` path, any ``::`` names, and one
#: optional parameter id, which may itself hold `` - ``, so its bracket is closed
#: at the first ``]`` the separator follows.
_PYTEST_ITEM_RE = re.compile(
    r"^(?P<word>FAILED|ERROR) (?P<nodeid>[^\s:\[\]]+\.py(?:::[^\s:\[\]]+)*(?:\[.*?\])?)(?: - |$)"
)


def pytest_items(*streams):
    """The findings pytest's own summary names in a failing command's output.

    Returns ``(items, kind)``: sorted ``FAILED <node id>`` / ``ERROR <node id>``
    strings, each redacted and bounded, and the kind of set they are -- or
    ``None`` when the set cannot be compared with another commit's. That is
    when no summary names anything, when more than one summary or stop banner
    appears (two sessions, which one session's numbers cannot describe), when a
    session stopped early for anything but collection errors (``-x``, a
    keyboard interrupt), or when there are more findings than the outcome keeps.

    Only the summary section is read, so a test's captured output above it is
    never a finding. The items are still the repository's own text: they refine
    which already-failing check a commit is the origin of, and never decide
    whether a check failed.
    """
    items, summaries, stops = set(), 0, []
    for text in streams:
        inside = False
        for line in (text or "").splitlines():
            if _PYTEST_SUMMARY_RE.match(line):
                inside, summaries = True, summaries + 1
                continue
            stop = _PYTEST_STOP_RE.match(line)
            if stop:
                stops.append(stop.group("text"))
            if not inside:
                continue
            if stop or _PYTEST_BANNER_RE.match(line) or _PYTEST_STATS_RE.match(line):
                inside = False
                continue
            found = _PYTEST_ITEM_RE.match(line)
            if found:
                items.add(_redacted(f"{found.group('word')} {found.group('nodeid')}")[:MAX_ITEM_CHARS])
    if not items:
        return [], None
    kind = None
    if summaries == 1 and len(items) <= MAX_ITEMS:
        if not stops:
            kind = PYTEST_ITEMS
        elif len(stops) == 1 and _PYTEST_COLLECTION_STOP_RE.match(stops[0]):
            kind = PYTEST_COLLECTION_ITEMS
    return sorted(items), kind


def _redacted(text: str) -> str:
    text = PRIVATE_KEY_BLOCK.sub("[REDACTED:private_key_block]", text)
    return CREDENTIAL_SHAPES_COMBINED.sub(lambda m: f"[REDACTED:{m.lastgroup}]", text)


def bounded_output(text) -> str:
    """One stream of a failing command: redacted, the middle dropped, redacted again.

    Redacting first means a cut can never leave a redactable prefix behind;
    redacting again catches a shape the join itself made."""
    text = _redacted(text or "")
    limit = FAILURE_OUTPUT_HEAD_CHARS + FAILURE_OUTPUT_TAIL_CHARS
    if len(text) <= limit:
        return text
    omitted = len(text) - limit
    return _redacted(text[:FAILURE_OUTPUT_HEAD_CHARS] + f"\n[... {omitted} characters omitted ...]\n"
                     + text[-FAILURE_OUTPUT_TAIL_CHARS:])


def run_declared(repo_root: Path, entry: dict, tools: Tools, timeout, *, is_setup: bool,
                 failure_output=None) -> dict:
    """Run one repository-declared command.

    This executes repository content by design -- a smoke that does not run the
    repository's own commands is not a smoke. It runs only after the code has
    already landed on the default branch, in a job that holds no credential.

    When it exits non-zero, a bounded copy of its output is appended to
    ``failure_output``, if given. That copy is for a person reading why: it never
    reaches the check, the outcome or the signature, which must stay identical
    across two runs whose output differs by a timestamp. Only the findings
    :func:`pytest_items` names do.
    """
    name = entry["name"]
    cid = f"setup:{name}" if is_setup else name
    proc, infra, spent = _bounded_run(tools, entry["run"], repo_root, timeout, cid, shell=True)
    if spent:
        return spent
    if infra:
        return _check(cid, "INFRA_UNAVAILABLE", infra, f"{name!r} could not be executed")
    if proc.returncode == 0:
        return _check(cid, "PASS", "PASS", f"{name!r} exited 0")
    if failure_output is not None:
        failure_output.append({"check": cid, "exit": proc.returncode,
                               "stdout": bounded_output(proc.stdout),
                               "stderr": bounded_output(proc.stderr)})
    if is_setup:
        # A setup step is provisioning, not the subject under test. Its failure
        # is an outage by definition: nothing was measured about the code. The
        # outage pattern only says so in the detail, so it never changes the
        # reason a later run is compared on.
        outage_note = (" with an outage signature"
                       if INFRA_OUTPUT_RE.search(f"{proc.stdout}\n{proc.stderr}") else "")
        return _check(cid, "INFRA_UNAVAILABLE", f"SETUP_FAILED:{name}",
                      f"setup step {name!r} exited {proc.returncode}{outage_note}")
    # A declared command's output is never read for an outage. It is the
    # repository's own text: a pytest collection listing printed test ids
    # containing "Could not resolve host", and a real failure read as an outage
    # on sixteen merges in a row (operator decision, 2026-10-15).
    #
    # It is read for the findings pytest's summary names, from the whole
    # output rather than the kept copy: those are stable across two runs of one
    # commit, so they join the signature, and with a kind the breaker can tell
    # a new failure inside an already-red check from the one it inherited.
    items, kind = pytest_items(proc.stdout, proc.stderr)
    detail = f"{name!r} exited {proc.returncode}"
    if items:
        detail += f"; pytest names {len(items)} finding(s)" + ("" if kind else ", not comparable")
    check = _check(cid, "CODE_FAILURE", f"COMMAND_FAILURE:{name}:exit{proc.returncode}", detail,
                   items=items)
    if kind:
        check["item_kind"] = kind
    return check


# ---------- outcome -------------------------------------------------------------

def signature(checks) -> str:
    """Deterministic digest of the CODE failures only. Infrastructure never
    contributes: an outage must not change the identity of a code failure."""
    failing = [[c["id"], c["reason"], c["items"]] for c in checks if c["status"] == "CODE_FAILURE"]
    failing.sort()
    return hashlib.sha256(json.dumps(failing, sort_keys=True).encode("utf-8")).hexdigest()


def classify(checks) -> str:
    statuses = {c["status"] for c in checks}
    if "INFRA_UNAVAILABLE" in statuses:
        return "INFRA_UNAVAILABLE"
    if "CODE_FAILURE" in statuses:
        return "CODE_FAILURE"
    return "PASS"


REPEATED_INFRA_PREFIX = "REPEATED_INFRA:"


def infra_reasons(result) -> frozenset:
    """The ``(check id, reason)`` pairs an outcome reports as INFRA_UNAVAILABLE."""
    if not isinstance(result, dict):
        return frozenset()
    return frozenset(
        (str(c.get("id")), str(c.get("reason")))
        for c in result.get("checks") or []
        if isinstance(c, dict) and c.get("status") == "INFRA_UNAVAILABLE"
    )


def _measured_checks(result):
    """The checks of an outcome that proved which commit it measured, or ``None``.

    Evidence is read from files, so every check must have the shape this module
    writes before any of it is rewritten or signed. ``signature`` sorts the
    findings, so a finding that is not text could raise instead of deciding.
    """
    checks = result.get("checks")
    if not (isinstance(checks, list) and checks and all(
            isinstance(c, dict) and isinstance(c.get("items"), list)
            and all(isinstance(item, str) for item in c["items"])
            and all(isinstance(c.get(k), str) for k in ("id", "status", "reason", "detail"))
            for c in checks)):
        return None
    if checks[0]["id"] != "identity" or checks[0]["status"] != "PASS":
        return None
    return checks


def promote_repeated_infra(result, previous):
    """The same INFRA reason on two consecutive commits is a code failure.

    Operator decision, 2026-10-15: an outage that is still there on the next
    commit is not an outage. ``result`` is promoted only when it and
    ``previous`` are both INFRA_UNAVAILABLE outcomes for two different commits,
    both proved which commit they measured, both ran the same smoke plan, and
    both report exactly the same non-empty set of INFRA ``(check id, reason)``
    pairs. Each of those checks then becomes CODE_FAILURE with the reason
    ``REPEATED_INFRA:<reason>`` and the signature is rebuilt over the result.
    Anything short of that returns ``result`` itself, unchanged.

    It is pure: it reads two outcome documents and never runs anything. The
    breaker applies it, so a promoted failure still needs the confirming rerun
    and the parent comparison before anything is reverted.
    """
    if not (isinstance(result, dict) and isinstance(previous, dict)):
        return result
    if result.get("outcome") != "INFRA_UNAVAILABLE" or previous.get("outcome") != "INFRA_UNAVAILABLE":
        return result
    if result.get("sha") == previous.get("sha") or result.get("source") != previous.get("source"):
        return result
    measured = _measured_checks(result)
    if measured is None or _measured_checks(previous) is None:
        return result
    repeated = infra_reasons(result)
    if not repeated or repeated != infra_reasons(previous):
        return result
    checks = []
    for check in measured:
        if check["status"] == "INFRA_UNAVAILABLE":
            check = {**check, "status": "CODE_FAILURE",
                     "reason": REPEATED_INFRA_PREFIX + check["reason"],
                     "detail": f"the same reason on the previous commit: {check['detail']}"}
        checks.append(check)
    # Every INFRA check is now a CODE_FAILURE, so the outcome is one too.
    return {**result, "checks": checks, "outcome": classify(checks),
            "signature": signature(checks), "promoted_from": "INFRA_UNAVAILABLE"}


BUDGET_NOTE = "the budget ran out; the remaining steps were not run"


def run_smoke(repo_root, expected_sha: str, tools: Tools | None = None, failure_output=None) -> dict:
    repo_root = Path(repo_root)
    tools = tools or Tools()
    started = time.monotonic()
    clock = getattr(tools, "clock", time.monotonic)
    opened = clock()
    checks = [check_identity(repo_root, expected_sha, tools)]
    source = "none"
    note = ""

    if checks[0]["status"] != "PASS":
        # Without a proven identity nothing that follows can be attributed to
        # this SHA, so nothing that follows is run.
        return _finish(checks, expected_sha, started, source, "identity unproven; no checks were run")

    try:
        declared = load_smoke_config(repo_root, expected_sha)
    except SmokeConfigError as exc:
        status = "CODE_FAILURE" if exc.reason == "SMOKE_CONFIG_INVALID" else "INFRA_UNAVAILABLE"
        checks.append(_check("smoke-config", status, exc.reason, exc.detail))
        return _finish(checks, expected_sha, started, "declared", "")
    except gitobject.GitUnavailable as exc:
        checks.append(_check("smoke-config", "INFRA_UNAVAILABLE", "GIT_ERROR", str(exc)))
        return _finish(checks, expected_sha, started, source, "")

    try:
        plan = build_plan(repo_root, expected_sha, tools, declared)
    except gitobject.GitUnavailable as exc:
        checks.append(_check("derive", "INFRA_UNAVAILABLE", "GIT_ERROR", str(exc)))
        return _finish(checks, expected_sha, started, source, "")
    source = plan["source"]

    if declared is not None and declared["history"] == "full":
        checks.append(check_history(repo_root, tools))
        if checks[-1]["status"] != "PASS":
            # The checks that read recorded history would fail for want of it,
            # and that failure would read as the code's.
            return _finish(checks, expected_sha, started, source,
                           "the declared history is missing; the checks were not run")

    if not plan["commands"]:
        checks.append(_check(
            "smoke", "PASS", "NO_SMOKE_DEFINED",
            "this repository declares no .github/aeos-smoke.json and matched no language default, "
            "so no executable smoke exists for this commit",
        ))
        note = ("NO_SMOKE_DEFINED: the rail ran and found nothing to run. This is a PASS, but it is "
                "not evidence that the commit works.")
        return _finish(checks, expected_sha, started, source, note)

    timeout = plan["timeout_seconds"]
    # Stop early enough to write the outcome before the workflow's step bound,
    # which is the same budget: a run that outgrows it ends typed, not killed.
    budget = Budget(opened + plan["budget_minutes"] * 60 - BUDGET_MARGIN_SECONDS, timeout, clock)

    notes = [note] if note else []
    for entry in plan["setup"]:
        check = run_declared(repo_root, entry, tools, budget, is_setup=True,
                             failure_output=failure_output)
        if check["reason"] == "SMOKE_BUDGET_EXHAUSTED":
            checks.append(check)
            return _finish(checks, expected_sha, started, source, BUDGET_NOTE)
        if check["status"] == "PASS":
            checks.append(check)
            continue
        if entry.get("best_effort"):
            # A best-effort step is provisioning that something else can report
            # on. Recording its failure as a check would make the whole run
            # INFRA_UNAVAILABLE even when the tool it was fetching turned out to
            # be present already and the check ran clean -- an outcome decided by
            # a step whose failure nothing depends on. The dependent check speaks
            # for itself; this only leaves a note.
            notes.append(f"{entry['name']}: {check['reason']} (best effort; "
                         "the dependent check reports whether it mattered)")
            continue
        checks.append(check)
        # A repository declared this step as a prerequisite. Running the checks
        # anyway would produce a defect report from a machine that is not in a
        # fit state to report one.
        return _finish(checks, expected_sha, started, source,
                       "a declared setup step failed; the checks were not run")
    note = " | ".join(notes)

    for entry in plan["commands"]:
        builtin = BUILTINS.get(entry.get("run")) if entry.get("builtin") else None
        if builtin is not None:
            check = builtin(repo_root, tools, budget, plan.get("python_targets") or [])
        else:
            check = run_declared(repo_root, entry, tools, budget, is_setup=False,
                                 failure_output=failure_output)
        checks.append(check)
        if check["reason"] == "SMOKE_BUDGET_EXHAUSTED":
            return _finish(checks, expected_sha, started, source, BUDGET_NOTE)
    return _finish(checks, expected_sha, started, source, note)


def _finish(checks, sha, started, source, note) -> dict:
    outcome = classify(checks)
    return {
        "schema_version": SCHEMA_VERSION,
        "check_context": CHECK_CONTEXT,
        "sha": sha,
        "outcome": outcome,
        "source": source,
        "note": note,
        "signature": signature(checks) if outcome == "CODE_FAILURE" else None,
        "checks": checks,
        "duration_seconds": round(time.monotonic() - started, 3),
    }


def render(result: dict) -> str:
    lines = [
        f"## {CHECK_CONTEXT}",
        "",
        f"- sha: `{result['sha']}`",
        f"- outcome: **{result['outcome']}**",
        f"- smoke source: `{result['source']}`",
        f"- duration: {result['duration_seconds']}s",
    ]
    if result.get("signature"):
        lines.append(f"- signature: `{result['signature']}`")
    if result.get("note"):
        lines += ["", f"> {result['note']}"]
    lines += ["", "| check | status | reason |", "| --- | --- | --- |"]
    for check in result["checks"]:
        lines.append(f"| `{check['id']}` | {check['status']} | `{check['reason']}` |")
    for check in result["checks"]:
        if check["status"] != "PASS" and check["items"]:
            lines += ["", f"<details><summary>{check['id']} findings</summary>", ""]
            lines += [f"- `{item}`" for item in check["items"][:50]]
            lines += ["", "</details>"]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="AEOS post-merge smoke of an exact merged SHA.")
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--expected-sha", required=True)
    ap.add_argument("--out")
    ap.add_argument("--summary-file")
    ap.add_argument("--declared-history", action="store_true",
                    help="print history=<shallow|full> and budget_minutes=<n> as declared at the SHA, "
                         "and run nothing")
    args = ap.parse_args(argv)

    if args.declared_history:
        declared = declared_checkout(args.repo_root, args.expected_sha.strip().lower())
        sys.stdout.write(f"history={declared['history']}\nbudget_minutes={declared['budget_minutes']}\n")
        return 0

    failures: list[dict] = []
    result = run_smoke(args.repo_root, args.expected_sha.strip().lower(), failure_output=failures)
    if result["outcome"] == "PASS":
        # A best-effort step can fail inside a passing run; a passing outcome
        # file stays exactly what it was.
        failures = []
    text = render(result)
    if failures and args.out:
        text += ("\n> Each failing command's own output, bounded and redacted, is kept in the outcome "
                 "file's `failure_output`. It decides nothing.\n")
    sys.stdout.write(text)
    if args.out:
        # Beside the outcome, never inside it: no check, outcome or signature
        # reads it, and the job log never carries it.
        document = {**result, "failure_output": failures} if failures else result
        Path(args.out).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    if args.summary_file:
        try:
            with open(args.summary_file, "a", encoding="utf-8") as handle:
                handle.write(text)
        except OSError as exc:
            sys.stdout.write(f"could not write the step summary: {exc}\n")
    return EXIT[result["outcome"]]


if __name__ == "__main__":
    raise SystemExit(main())
