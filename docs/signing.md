# Release signing

The repository includes a manual `signed-build` GitHub Actions workflow. It builds and tests the exact commit, launches the packaged single-file application before signing, signs only `DBDR.PcCheck.exe`, verifies the resulting Authenticode chain, launches the signed file again, then uploads a ZIP and SHA-256 sidecar. A raw single-file `.exe` is not used as the transport artifact because transformations or truncation after build invalidate the appended .NET bundle.

The workflow uses Microsoft Artifact Signing with GitHub OpenID Connect. It does not store a PFX or private key in the repository.

## Required Azure setup

1. Create and identity-validate an Artifact Signing account and public-trust certificate profile.
2. Create a Microsoft Entra application/service principal and grant it `Artifact Signing Certificate Profile Signer` on that certificate profile.
3. Add a federated GitHub credential restricted to this repository and the environment/branch policy selected by the operator.
4. Configure these GitHub Actions secrets:
   - `AZURE_CLIENT_ID`
   - `AZURE_TENANT_ID`
   - `AZURE_SUBSCRIPTION_ID`
5. Configure these GitHub Actions variables:
   - `ARTIFACT_SIGNING_ENDPOINT` (for example the regional `https://...codesigning.azure.net/` endpoint returned by the account)
   - `ARTIFACT_SIGNING_ACCOUNT_NAME`
   - `ARTIFACT_SIGNING_CERTIFICATE_PROFILE_NAME`
6. Restrict the `signed-build` workflow with a protected GitHub environment and required reviewer before production use.

Run the workflow manually for an approved commit. A successful ordinary development build is not signed, and the project must never describe it as signed. Self-signed certificates are suitable only for private development trust stores and are not used by this workflow.

Primary references:

- [Microsoft Artifact Signing integrations](https://learn.microsoft.com/en-us/azure/artifact-signing/how-to-signing-integrations)
- [Microsoft code-signing options for Windows developers](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options)
- [Official Azure Artifact Signing GitHub Action](https://github.com/Azure/artifact-signing-action)
