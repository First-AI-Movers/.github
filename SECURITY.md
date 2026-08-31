# Security Policy — First AI Movers (organization default)

This is the **organization-wide default** security policy for **First AI Movers**. GitHub applies it to any `First-AI-Movers/*` repository — public, internal, or private — that does **not** have its own `SECURITY.md`. The public requirement falls on the `.github` repository that serves the default, not on the repository receiving it.

**This does not narrow how to report a vulnerability.** The contact below is the organization's reporting route for every First-AI-Movers repository, public or private.

> **A repository's own `SECURITY.md` always overrides this default.** Active code/content repos (e.g. the application, the publishing engine, the article archive, the toolkit) maintain their own `SECURITY.md` — and, where applicable, their own incident-response runbook — with repo-specific scope and contacts. Use the repository's own policy if it has one; this default is the fallback for low-surface, static, profile, placeholder, and new repositories.

## Reporting a vulnerability

If you discover a security vulnerability — exposed credentials, an insecure configuration, or any issue that could lead to harm — please report it **privately and responsibly**:

- **Email:** `info@firstaimovers.com` with the subject `SECURITY: <short title>`.
- **Do not** open a public issue, pull request, or discussion for a suspected vulnerability.

> *Operator follow-up:* a dedicated `security@firstaimovers.com` alias is recommended but **not yet confirmed to exist** — until it is provisioned, use the general `info@` address above. (`TODO(operator): provision a dedicated security@firstaimovers.com mailbox or equivalent and update this default.`)

### What to include

- A clear description of the issue and its potential impact.
- The repository / component affected and steps to reproduce (a minimal, synthetic reproduction is best).
- Any preconditions, and a suggested remediation if you have one.

### What **not** to include

- **No secrets, credentials, tokens, or keys.** **No personal data (PII).** No private payloads or internal data. Reference such values by *location/name*, never by value — if something sensitive was exposed, say so **without pasting it**.

## Coordinated disclosure & response

- We ask reporters to follow **coordinated disclosure**: please do not disclose publicly until we have had a reasonable opportunity to investigate and coordinate a fix.
- **Acknowledgement target:** we aim to acknowledge a report within **3 business days**. This is a good-faith target, **not** a contractual guarantee.
- There is **no bug-bounty program**; we appreciate responsible reports and will credit reporters who request it.

## Scope & limits

This default is displayed on any First-AI-Movers repository — whatever its visibility — that lacks its own `SECURITY.md`, and the reporting route above applies to every one of them regardless. It does **not** itself provide an incident-response runbook for every repo — active repositories are expected to adopt their own `SECURITY.md` and incident-response runbook. Reports about a specific product/repository are best sent with that repository named in the subject.
