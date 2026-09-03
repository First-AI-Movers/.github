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

**One exception, and it is deliberate.** Deleting a control-plane path *in this
repository* fails with `CONTROL_PLANE_CHANGE_REQUIRES_OPERATOR` and needs a
person. A deletion has no bytes, so no content floor can measure it, and this
deletion reaches the gate that judges the whole organization. It is the only
human gate left in the merge path.

## Proof

```bash
PYTHONPATH=aeos python3 -m pytest aeos/tests/
```

Everything under `aeos/` is pure stdlib plus a YAML safe loader: no network, no
clock, no subprocess beyond `git`, no filesystem writes. A change that needs any
of those is almost certainly in the wrong place.

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
