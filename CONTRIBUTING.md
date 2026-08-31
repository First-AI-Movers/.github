# Contributing — First AI Movers (organization default)

This is the **organization-wide default** contribution guide for **First AI Movers**. GitHub applies it to any **public** `First-AI-Movers/*` repository that does **not** have its own `CONTRIBUTING.md`. GitHub applies a default community-health file only to **public** repositories that do not have their own copy. A private or internal repository inherits nothing and must ship its own.

> **A repository's own `CONTRIBUTING.md` always overrides this default.** Where a repository ships its own guide, follow that one — this default is the fallback for low-surface, static, profile, placeholder, and new repositories.

## Repository canon outranks this file

A First-AI-Movers repository is governed by the canon it carries in its own root — typically `AGENTS.md` (the instruction surface for human and AI contributors), `CLAUDE.md` (the Claude Code entry point), and `ROADMAP.md` (live work state). **Where those files are present, they outrank this default.** Read them before opening an issue or a pull request: they carry the repository's actual scope, review contract, and stop conditions. This file states only what holds when a repository has said nothing more specific.

## How changes reach a default branch

The organization ruleset **Protect main branches** governs the default branch of First-AI-Movers repositories. Where it is in force, it means:

- **Every change to the default branch goes through a pull request.** Direct pushes are rejected.
- **The default branch cannot be deleted, and it cannot be force-pushed.**
- **Linear history is required** on the default branch.

Ruleset coverage is applied per repository and can lag behind a newly created one. Required status checks are configured **per repository**, not organization-wide, so they differ between repositories. To see exactly what applies where you are working, read **Settings → Rules**, or ask GitHub directly:

```bash
# Rulesets — organization-level and repository-level rules that apply to the branch
gh api repos/<owner>/<repo>/rules/branches/<default-branch>

# Classic branch protection — a separate, older mechanism the call above does NOT return
gh api repos/<owner>/<repo>/branches/<default-branch>/protection
```

**Both are needed: they are independent mechanisms and either can block your pull request.** The first command returns ruleset-derived rules only. A non-empty answer there is *not* the whole picture — a repository can return a healthy list of ruleset rules while its **required status checks** live in classic protection and never appear in that output at all. `First-AI-Movers/articles` was in exactly that state when this guide was last verified (2026-08-31): the rules endpoint returned ruleset rules while its merge-blocking status checks were visible only through the second command. That is a snapshot, not a standing fact — run both commands against the repository you are working in rather than trusting either this example or the first command alone. **A `404` from the second command is only meaningful if you could otherwise read the repository's settings.** GitHub returns `404` both when classic protection genuinely is absent *and* when the caller lacks repository **Administration: read** permission — it deliberately does not distinguish "not there" from "not yours to see", so an under-permissioned contributor can read a `404` as "unprotected" and miss merge-blocking rules. Treat `404` as absence only when the first command succeeded for the same repository and your token carries Administration read; otherwise treat it as **unknown** and ask a repository admin.

What those commands return together is what will actually be enforced against your pull request. Treat them, not this file, as the authority on any given repository.

## Working agreement

- **Open the work before you do it.** Where the repository has an issue tracker, use it, and state the outcome you intend — not just the change you plan to make.
- **One concern per pull request.** Keep the diff reviewable and the intent legible from the title.
- **Say what you verified.** Describe how you checked the change, not only what you changed.
- **Respect the repository's stated boundaries.** Do not add code, workflows, or generated artifacts to a repository whose own canon says it does not host them.
- **Never commit secrets, credentials, tokens, keys, or personal data.** Reference sensitive values by location or name, never by value.

## Security issues are not pull requests

Do **not** report a suspected vulnerability through an issue, a pull request, or a discussion. Follow the organization [`SECURITY.md`](./SECURITY.md): email `info@firstaimovers.com` with the subject `SECURITY: <short title>`.

## Adopting this contract in your own repository

The canonical adoption and onboarding contract is the client-neutral **GitHub-native adoption kit** maintained at [`First-AI-Movers/agent-toolkit` → `templates/github-native/`](https://github.com/First-AI-Movers/agent-toolkit/tree/main/templates/github-native). **`agent-toolkit` is a private repository**, so that link resolves for organization members and returns `404` to everyone else — the kit exists, but it is not public. If you are outside the organization and need it, ask at `info@firstaimovers.com`.

It is **projection-only**: it grants no authority, mutates no ruleset, and installs no GitHub App. Use it when standing up a new repository or aligning an existing one — this default is not an onboarding guide, only the floor that applies until a repository defines its own.

## Code of conduct

All participation in First-AI-Movers repositories is covered by the organization [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md).
