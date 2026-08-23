[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("DBDR-YaraPackTest-" + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
$key = $null
$verificationKey = $null
$archive = $null
try {
    $rulesPath = Join-Path $temporaryRoot 'rules.yar'
    $keyPath = Join-Path $temporaryRoot 'private.pem'
    $packPath = Join-Path $temporaryRoot 'test.dbdrrules'
    [IO.File]::WriteAllText(
        $rulesPath,
        'rule DBDR_Signer_Smoke_Test { strings: $a = "dbdr-signer-test" condition: $a }',
        [Text.UTF8Encoding]::new($false))

    $curve = [Security.Cryptography.ECCurve]::CreateFromValue('1.2.840.10045.3.1.7')
    $key = [Security.Cryptography.ECDsa]::Create($curve)
    [IO.File]::WriteAllText($keyPath, $key.ExportECPrivateKeyPem(), [Text.UTF8Encoding]::new($false))

    $result = & (Join-Path $PSScriptRoot 'New-DbdrYaraRulePack.ps1') `
        -RulesPath $rulesPath `
        -OutputPath $packPath `
        -PackId dbdr-ci `
        -Version 1.0.0 `
        -KeyId ci-key `
        -PrivateKeyPemPath $keyPath `
        -ExpiresUtc ([DateTimeOffset]::UtcNow.AddDays(1))

    if ($result.OutputPath -ne $packPath -or -not [IO.File]::Exists($packPath)) {
        throw 'Rule-pack signer did not create the expected output.'
    }

    $archive = [IO.Compression.ZipFile]::OpenRead($packPath)
    $entries = @($archive.Entries)
    $names = @($entries | ForEach-Object FullName | Sort-Object)
    if ($names.Count -ne 3 -or ($names -join ',') -ne 'manifest.json,rules.yar,signature.p1363') {
        throw 'Rule-pack signer created an unexpected archive layout.'
    }

    function Read-EntryBytes([string]$name) {
        $entry = $archive.GetEntry($name)
        if ($null -eq $entry) {
            throw "Missing pack entry: $name"
        }

        $input = $entry.Open()
        $output = [IO.MemoryStream]::new()
        try {
            $input.CopyTo($output)
            return $output.ToArray()
        }
        finally {
            $input.Dispose()
            $output.Dispose()
        }
    }

    $manifest = Read-EntryBytes 'manifest.json'
    $rules = Read-EntryBytes 'rules.yar'
    $signature = Read-EntryBytes 'signature.p1363'
    $manifestObject = [Text.Encoding]::UTF8.GetString($manifest) | ConvertFrom-Json
    $rulesHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($rules))
    if ($manifestObject.rulesSha256 -ne $rulesHash -or $signature.Length -ne 64) {
        throw 'Rule-pack signer produced an invalid hash or signature size.'
    }

    $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
    $payloadStream = [IO.MemoryStream]::new()
    $payloadWriter = [IO.BinaryWriter]::new($payloadStream, $strictUtf8, $true)
    try {
        $payloadWriter.Write($strictUtf8.GetBytes("DBDR-YARA-PACK-V1`0"))
        $payloadWriter.Write([int]$manifest.Length)
        $payloadWriter.Write($manifest)
        $payloadWriter.Write([int]$rules.Length)
        $payloadWriter.Write($rules)
        $payloadWriter.Flush()
        $payload = $payloadStream.ToArray()
    }
    finally {
        $payloadWriter.Dispose()
        $payloadStream.Dispose()
    }

    $verificationKey = [Security.Cryptography.ECDsa]::Create()
    $publicKeyBytes = [Convert]::FromBase64String($result.PublicKeySpkiBase64)
    if (-not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
            $publicKeyBytes,
            $key.ExportSubjectPublicKeyInfo())) {
        throw 'Rule-pack signer returned a public key that differs from the supplied private key.'
    }
    $bytesRead = 0
    $verificationKey.ImportSubjectPublicKeyInfo($publicKeyBytes, [ref]$bytesRead)
    if ($bytesRead -ne $publicKeyBytes.Length -or $verificationKey.KeySize -ne 256) {
        throw 'Rule-pack signer did not return a valid P-256 public key.'
    }

    if (-not $verificationKey.VerifyData(
            $payload,
            $signature,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) {
        throw 'Rule-pack signer produced a signature that did not verify.'
    }

    Write-Host 'Offline YARA rule-pack signer smoke test passed.'
}
finally {
    if ($null -ne $archive) {
        $archive.Dispose()
    }
    if ($null -ne $key) {
        $key.Dispose()
    }
    if ($null -ne $verificationKey) {
        $verificationKey.Dispose()
    }
    if ([IO.Directory]::Exists($temporaryRoot)) {
        [IO.Directory]::Delete($temporaryRoot, $true)
    }
}
