# Repository guidance

This repository contains a consent-based, read-only Windows evidence collector for DBDR PC checks.

## Engineering rules

- Collection modules must be read-only and independently cancellable.
- Never collect credentials, browser data, chat contents, clipboard data, screenshots, arbitrary documents, or raw process memory.
- New evidence categories require a corresponding update to `PRIVACY.md` and `docs/evidence-schema.md`.
- A missing artifact is not evidence of cheating. Record collection failures explicitly.
- A single weak indicator must never produce a cheating verdict.
- Do not add process termination, service modification, driver installation, log clearing, injection, or debugger attachment.
- Keep file paths redacted through `PathRedactor`; never serialize a Windows username.

## Code review rules

- Reject changes that broaden collection without a documented purpose and privacy review.
- Treat evidence integrity, path redaction, archive traversal, command injection, and secret leakage as high-risk surfaces.
- Require tests for new redaction logic, evidence schemas, and module-failure behavior.
