# First-AI-Movers/.github

This repository holds the GitHub organization profile for **First AI Movers**.

The displayed content is in [`profile/README.md`](./profile/README.md), which GitHub renders at the top of <https://github.com/First-AI-Movers>.

For canonical company information, see:

- Company website: <https://www.firstaimovers.com>
- GitHub Pages bridge: <https://first-ai-movers.github.io/>

## Organization-wide defaults

GitHub applies the files below to any `First-AI-Movers/*` repository — **public, internal, or private** — that does **not** ship its own copy. A repository's own file always overrides the default.

**The public requirement is on *this* repository, not on the destinations.** GitHub serves organization defaults only from a **public** `.github` repository — this one is public — and once that holds, the defaults reach every repository the organization owns, whatever its own visibility. A private repository with no `CODE_OF_CONDUCT.md` of its own is covered by the one here.

There is deliberately no "check it yourself" command here. `GET /orgs/{org}/repos` returns only the repositories the **calling token** can see and returns `200` either way, so an outsider — or a member without access to every private repository — would get a smaller split, possibly zero private, with nothing in the response indicating the view was partial. Obtaining the true split requires visibility of **every** repository in the organization — a permission, not a role: an organization owner is guaranteed to have it, and so is anyone else granted access to them all. Publishing that query in a public README would invite exactly the wrong conclusion.

| File | Applies to any repository with no own copy |
|---|---|
| [`SECURITY.md`](./SECURITY.md) | how to report a vulnerability privately |
| [`CONTRIBUTING.md`](./CONTRIBUTING.md) | how a change reaches a default branch |
| [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) | Contributor Covenant v2.1, org enforcement contact |

## Adoption and onboarding contract

The canonical, client-neutral contract for standing up a new repository — or aligning an existing one — is the **GitHub-native adoption kit** at [`First-AI-Movers/agent-toolkit` → `templates/github-native/`](https://github.com/First-AI-Movers/agent-toolkit/tree/main/templates/github-native). **`agent-toolkit` is private**, so this link resolves for anyone granted access to that repository — an organization member with access, or an outside collaborator — and returns `404` to everyone else, including organization members who have not been granted access. Membership is not the test; repository permission is. This repository is public; that one is not.

It is projection-only: it grants no authority, mutates no ruleset, and installs no GitHub App. Repository class and sensitivity are owned by the federation registry and mirrored one-way onto GitHub organization properties — GitHub is never written back into the registry.

## Organization-owned merge rails

This repository also holds the organization's own merge automation, because a
required workflow can only be served from a repository every target can read —
and only this one is public.

| Rail | What it does |
|---|---|
| [`.github/workflows/aeos-merge-ready.yml`](./.github/workflows/aeos-merge-ready.yml) | the **required** pre-merge verdict, injected onto every organization repository by ruleset as a Required Workflow. Trusted policy from this repository's `main` evaluates the candidate's changed bytes as data, inside a 60-second ceiling, and reports one typed reason on failure — see [`aeos/README.md`](./aeos/README.md) |
| [`.github/workflows/aeos-main-smoke.yml`](./.github/workflows/aeos-main-smoke.yml) | post-merge smoke of the exact merged SHA, plus the deterministic circuit breaker and automatic revert — see [`aeos/main-smoke.md`](./aeos/main-smoke.md) for the ~12-line per-repository caller |

Both rails are repository-agnostic: they depend on no file existing in the
repository they run against, and a brand-new repository passes. Candidate code
is treated as data by the merge gate and is never executed by it.

Apart from these, the repo intentionally stays minimal — organization defaults, profile metadata, and the instruction surface for agents working here ([`AGENTS.md`](./AGENTS.md)).
