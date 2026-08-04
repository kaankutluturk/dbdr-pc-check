# Threat model

## Goals

- Make routine PC-check evidence collection consistent.
- Preserve the difference between an observation and a moderation conclusion.
- Minimize unrelated personal data.
- Make accidental post-collection modification detectable through a manifest.
- Continue collecting when a single Windows source is unavailable.

## Non-goals

- Proving that a machine is clean.
- Defeating a hostile kernel or compromised operating system.
- Detecting DMA hardware conclusively.
- Performing memory forensics or reverse engineering.
- Replacing staff review or an appeal process.

## Trust boundaries

The v0.1 collector runs inside the checked Windows installation. A sufficiently privileged adversary can manipulate APIs, files or registry results. The SHA-256 manifest detects changes after packaging but does not prove that the source operating system supplied truthful data.

Future direct upload should use a one-use case token, local authenticated encryption and a server receipt covering the uploaded bundle hash. A private key must never be embedded in the public client.

## Abuse cases

- A staff member requests collection outside an authorized case.
- A bundle exposes unrelated personal paths.
- A malicious fork impersonates the official collector.
- A moderation decision treats one weak artifact as conclusive.
- A local attacker tampers with evidence before packaging.
- A build workflow or signing secret is compromised.

Mitigations include explicit scope, visible consent, redaction, signed releases, reproducible CI, manifest verification, access control and mandatory human review.
