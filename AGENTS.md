# AGENTS.md — `First-AI-Movers/.github`

Instruction surface for any AI coding agent working in this repository.

## What this repo is

Two unrelated things, both of which have to live here because GitHub serves them
only from a **public** `.github` repository:

1. **The organization profile and defaults** — `profile/README.md`, plus
   `SECURITY.md` / `CONTRIBUTING.md` / `CODE_OF_CONDUCT.md`, which apply to any
   `First-AI-Movers/*` repository that ships no copy of its own.
2. **The organization's merge control plane** — `aeos/`, run by
   `.github/workflows/aeos-merge-ready.yml` and `.github/workflows/aeos-main-smoke.yml`.

The second is why a change here is not ordinary.

## `aeos/` decides whether every other repository may merge

Every other repository's one required merge check is the App check `aeos-merge-judge`
(GitHub App 5453110, run in judge custody on a Development Cell; organization ruleset
22118963 has injected no Required Workflow since 2026-10-25). The judge evaluates this
repository's `aeos/` policy at `main` against the candidate, exactly as
`aeos-merge-ready` does here. A change to `aeos/` therefore still changes what is allowed
to merge in every repository at once.

Three properties hold, and none of them may be weakened:

- **Trusted policy, candidate data.** The gate checks out *this* repository at the
  base commit and evaluates the candidate repository's changed bytes as data. It
  never executes candidate code — workflow YAML is safe-loaded, candidate Python
  is read with `ast.parse`. A candidate must never be able to influence the
  verdict on itself.
- **The judge is the predecessor.** A pull request that changes the gate is judged
  by the copy of the gate already on `main`, never by its own. That is what "no
  self-approval" means here.
- **Typed, closed vocabulary.** Every route out of the gate reports one reason
  code from `REASON_CODES`. A bare traceback or an untyped non-zero exit is a
  defect, not a verdict.

`aeos/README.md` is the contract. Read it before changing anything under `aeos/`.

## PR lifecycle

Open the PR **ready**, arm squash auto-merge **in the same step while the gate is
still pending** (GitHub refuses to arm an already-mergeable PR), do not request
review, do not wait. In this repository `aeos-merge-ready` is the one merge-blocking verdict;
in every other repository it is the App check `aeos-merge-judge`.

**Two exceptions, both deliberate, both in this repository only.** Each fails with
`CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR`:

- **Who may change the judge.** A control-plane change here (the protected-decision set
  below) is judged on its content only when
  the operator decided it. Either the trusted evidence names a pinned operator principal (type User) as the
  PR author *and* as the run's actor, or the machine principal authored, ran and
  committed it and the operator's latest decisive review **approves that exact head**
  (`aeos/operator_approval.py`). Anything else is refused, whatever the content.
  A machine carries the mechanics but never decides the policy that judges machines:
  it never approves, and an approval is stale after any push. So the operator is
  never asked to open, arm or babysit a policy PR; prepare it, open it as the machine,
  arm auto-merge, and put the decision in plain words at the top for his Approve.
- **Deleting a control-plane path.** A deletion has no bytes, so no content floor
  can measure it, and this deletion reaches the gate that judges the whole
  organization. It is refused whoever authors it; an organization administrator
  merges it under a ruleset bypass.

These are the only human gates in the merge path, and they are for genuine protected
decisions only (agent-toolkit #3052, operator directive 2026-10-20). The protected-decision set in
this repository is:

- **The judge** — every `aeos/*.py`, and any new file or directory under `aeos/`, because the
  judge puts `aeos/` first on its import path.
- **Its classification and trust data** — `aeos/standing-governor-policy.json`: roots, allowlist,
  members, operator principals and signer keys.
- **The seat ceilings** — `aeos/standing-seat-ceilings.json`, which grants standing seats their
  authority, except a removal that touches no kept seat (below).
- **The tests and their vectors** — `aeos/tests/**`. They are executable evidence that runs on
  whoever runs the suite, the operator's machine with his signing key included, and no static
  check can rule out a suite that passes without testing anything.
- **Every workflow and action** — `.github/workflows/**` and `.github/actions/**`: the merge-ready
  judge, and the main-smoke and revert rail, which holds the revert App's private key.
- **The gate and smoke configuration** — `.github/aeos-gate.json` and `.github/aeos-smoke.json`,
  which decide how a check behaves.
- **Every `.gitattributes`** — it rewrites the judge's checked-out bytes.
- **Every Python source and the test configuration** — any `*.py`, `*.pyc`, `*.pyw`, `*.so` or
  `*.pyd` anywhere in this repository (a `conftest.py` included), and the root `pytest.ini`,
  `pyproject.toml`, `setup.cfg`, `tox.ini`, `.pytest.ini`, `pytest.toml` and `.pytest.toml`, a
  deletion included. The proof commands run `python3 -m pytest` or `python3 -m unittest` from the
  repository root, and `-m` puts the current directory first on `sys.path`. So a root
  `pytest/__init__.py` or `json.py` would replace the runner or the standard library, and pytest
  loads a root `conftest.py` and reads the root configuration, on whoever runs the suite next. A
  `*.pth` file is listed too, as a conservative over-inclusion: it executes only from a site
  directory, which this repository is not.

Not a protected decision, so it merges on the gate verdict alone:

- every Markdown file directly in `aeos/` (no workflow runs it, the gate never reads it and nothing
  imports it);
- the root docs: `README.md`, `AGENTS.md`, `CLAUDE.md`, `CONTRIBUTING.md`, `SECURITY.md`,
  `CODE_OF_CONDUCT.md` and `profile/`;
- a seat-ceilings edit that only removes entries, with nothing else changed, where no removed entry
  shares its seat (repository, case-insensitive, and issue) with an entry that is kept. Such a removal
  only narrows authority and can never promote another entry for the same seat. An entry without
  a clean seat, or any other change to the file (deleting it included), stays protected.

Rulesets, branch protection and secrets are outside this repository and stay operator-governed.
No machine principal approves its own change; that is unchanged.

If any path in a pull request is protected, the whole pull request needs the operator. The same changes in a consumer
repository are judged on content and merge. `aeos/README.md` is the contract for
both.

When an owned next effect is temporarily blocked on a routine dependency — a
pending PR, a gate run, an AI review, or another owner — do exactly one of:
(a) execute the next dependency-ready effect; (b) send one bounded
GitHub-native handoff (an Issue or PR comment) to the existing known owner and
continue disjoint work; or (c) persist a typed wake predicate and yield to the
existing continuation machinery, which wakes exactly one successor when the
predicate changes (`DEPENDENCY_WAIT_PERSISTS_WAKE_PREDICATE`). A successor
session reconstructs from GitHub Issues, PRs and current `main` alone — no
transcript, no operator copy-paste, no operator relay
(`SESSION_ROLLOVER_RECONSTRUCTS_FROM_GITHUB`). A pending PR, gate, or review
state is never a session terminal and never a reason to return to the operator
for `continue`.

## Proof

```bash
PYTHONPATH=aeos python3 -m pytest aeos/tests/
```

Everything under `aeos/` is pure stdlib plus a YAML safe loader: no network, no
clock, no subprocess beyond `git`, no filesystem writes. A change that needs any
of those is almost certainly in the wrong place.

**One narrow, documented accommodation — the standing-governor derivation-policy
conjunct** (`aeos/derivation_policy.py`, decided by
`ADR:standing-governor-continuity-authority` in `agent-toolkit` and authorized by
issue `#1951` decision 5600051094 item 2): it runs `ssh-keygen -Y verify` (argv only, over
bytes the gate already read, against an allowed-signers file written from trusted
policy into a private temporary directory), reads the wall clock once to decide
signer expiry, and reads one committed data file, `aeos/standing-governor-policy.json`,
whose member list the gate regenerates from the candidate's base and head commits on
every evaluation and refuses as drift when it differs, and whose pinned signer
fingerprint it binds to the pinned public key. Nothing in it executes candidate
bytes. Editing that data file is a control-plane change like the judge's own source:
judged by the predecessor, never by the candidate.

**Adding a rule to the workflow policy carries two obligations.** Give it a
violation that must fire *and* a near-miss that must stay silent — a policy that
only ever says "no" is a wall, not a floor. And measure it against the live
population before shipping: a rule the organization's existing workflows already
fail blocks everyone, which is how the first cut of the action-pin rule flagged
23 of 68 workflows and had to be narrowed within the hour.

## Boundaries

- The profile and default files are **public**. Never write an internal hostname,
  internal path, private repository detail, or credential into this repository.
- Do not add application code, generated artifacts or unrelated workflows here.
- Ruleset mutation, organization settings and GitHub App installation are
  operator-governed effects; nothing in this repository grants them.
