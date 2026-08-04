# Security policy

## Development status

This project is pre-release software. Do not use development builds for enforcement decisions.

## Reporting vulnerabilities

Do not open a public issue for vulnerabilities that could expose player evidence, bypass redaction, permit command execution, or compromise release artifacts. Report those privately to the repository owner until DBDR establishes a dedicated security contact.

## High-risk areas

- evidence path redaction;
- archive and temporary-directory handling;
- executable hashing and signature inspection;
- future upload authentication and encryption;
- GitHub Actions and release signing; and
- any change that increases the amount of collected personal data.

Never commit signing certificates, private keys, access tokens, collected evidence bundles or real player fixtures.
