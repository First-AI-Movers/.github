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

`aeos-merge-ready` is injected as a **Required Workflow** by the organization
ruleset onto every repository in the organization. A change to `aeos/` changes
what is allowed to merge in all of them at once.

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
review, do not wait. `aeos-merge-ready` is the one merge-blocking verdict.

**Two exceptions, both deliberate, both in this repository only.** Each fails with
`CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR`:

- **Who may change the judge.** A control-plane change here (`aeos/**`,
  `.github/workflows/**`, `.github/actions/**`, `.github/aeos-gate.json`,
  `.github/aeos-smoke.json`) is judged on its content only when the trusted
  evidence names a pinned operator principal (type User) as the PR author *and*
  as the run's actor. A machine principal, any bot, or an empty or unreadable
  author or actor is refused, whatever the content — a machine never edits the
  policy that judges machines.
- **Deleting a control-plane path.** A deletion has no bytes, so no content floor
  can measure it, and this deletion reaches the gate that judges the whole
  organization. It is refused whoever authors it; an organization administrator
  merges it under a ruleset bypass.

These are the only human gates in the merge path. The same changes in a consumer
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
bytes. Editing that data file is a control-plane change like any other file under
`aeos/`: judged by the predecessor, never by the candidate.

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
