# Signed YARA rule packs

DBDR can load an offline `.dbdrrules` pack only after verifying its exact archive shape, validity interval, analysis-profile binding, rules hash and ECDSA signature against a public key embedded at build time. No rule pack is downloaded automatically. Raw `.yar` and `.yara` files remain available for local testing but are explicitly recorded as `operator-supplied-unverified`.

## Trust model

- The signing key is ECDSA P-256. The private key remains in the rule publisher's controlled signing environment and must never be committed, embedded in the client or copied into a case bundle.
- The client contains only a SubjectPublicKeyInfo public key. A key rotation therefore requires an approved rebuild.
- The pack signature uses SHA-256 and the fixed 64-byte IEEE P1363 `(r || s)` representation.
- The pack is bound to an exact `analysisProfileVersion`. An otherwise valid pack for another analyzer profile is rejected.
- Validity can be no longer than 366 days. Expired packs and packs created more than five minutes in the future are rejected.
- The portable client stores no machine-wide anti-rollback state. Version and expiry are verified and recorded, but an older still-valid pack for the same profile can be selected by the operator. Operational distribution must therefore publish approved pack/version pairs and retire superseded packs.

## Container format

The ZIP-compatible `.dbdrrules` file is at most 4 MiB and contains exactly three case-sensitive root entries—no directories or extra metadata files:

- `manifest.json`: strict UTF-8 JSON, at most 16 KiB;
- `rules.yar`: strict UTF-8, self-contained YARA rules, at most 4 MiB; and
- `signature.p1363`: exactly 64 bytes.

The manifest schema is `dbdr-yara-rule-pack/1` and has exactly these camel-case fields:

```json
{
  "schemaVersion": "dbdr-yara-rule-pack/1",
  "packId": "dbdr-production",
  "version": "1.2.3",
  "keyId": "rules-2026-01",
  "createdUtc": "2026-08-23T10:00:00.0000000+00:00",
  "expiresUtc": "2026-11-21T10:00:00.0000000+00:00",
  "analysisProfileVersion": "0.5.0",
  "rulesSha256": "UPPERCASE_HEX_SHA256_OF_RULES.YAR"
}
```

`packId` and `keyId` accept 1–64 ASCII letters, digits, dots, underscores or hyphens. `version` is numeric `major.minor.patch`. Both timestamps must be UTC. Unknown manifest fields, duplicate/missing ZIP entries, unsafe paths, invalid UTF-8 and YARA `include` directives are rejected.

The signed byte sequence is:

1. UTF-8 bytes `DBDR-YARA-PACK-V1` followed by one NUL byte;
2. four-byte little-endian signed integer containing the raw `manifest.json` byte length;
3. the exact raw `manifest.json` bytes;
4. four-byte little-endian signed integer containing the raw `rules.yar` byte length; and
5. the exact raw `rules.yar` bytes.

The manifest's `rulesSha256` is checked with a fixed-time comparison before the signature is accepted.

## Offline pack creation

Generate and retain the private key in the organization's approved secret/signing system. For a local test key, PowerShell 7 can import an externally generated PEM and create a compatible pack:

```powershell
.\tools\New-DbdrYaraRulePack.ps1 `
  -RulesPath .\rules\dbdr-production.yar `
  -OutputPath .\out\dbdr-production-1.2.3.dbdrrules `
  -PackId dbdr-production `
  -Version 1.2.3 `
  -KeyId rules-2026-01 `
  -PrivateKeyPemPath X:\protected\rules-2026-01-private.pem `
  -ExpiresUtc 2026-11-21T10:00:00Z
```

The script refuses to overwrite an existing output and prints the pack hash, rules hash and public SPKI key. It does not copy the private key into the pack.

## Build-time public key

Configure these GitHub Actions repository variables together:

- `YARA_RULE_PACK_KEY_ID`
- `YARA_RULE_PACK_PUBLIC_KEY_SPKI_BASE64`

The second value is base64 of the ECDSA public key's DER SubjectPublicKeyInfo bytes. Both ordinary CI packaging and the production signed-build workflow pass these values into the Windows assembly. The packaged-app self-test validates every embedded trust key and fails the workflow if a configured key is malformed or not P-256. If neither variable is configured, the application still runs the embedded baseline and unverified local rules, but it rejects every `.dbdrrules` pack as untrusted.

Pack signing and Authenticode application signing are separate trust domains. Use separately controlled keys and approval paths for them.

## Evidence and review

The case bundle stores only the ruleset identifier, SHA-256 and trust label. For a verified pack the identifier is `signed:{packId}@{version}` and the trust label is `ecdsa-p256-sha256-verified`. It does not copy rule contents, signatures, manifests, matched bytes or file content. A signed YARA match remains a review lead, never an automated cheating verdict.
