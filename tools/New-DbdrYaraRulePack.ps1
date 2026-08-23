[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$RulesPath,

    [Parameter(Mandatory)]
    [string]$OutputPath,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9_.-]{1,64}$')]
    [string]$PackId,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+$')]
    [string]$Version,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9_.-]{1,64}$')]
    [string]$KeyId,

    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$PrivateKeyPemPath,

    [Parameter(Mandatory)]
    [DateTimeOffset]$ExpiresUtc,

    [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+$')]
    [string]$AnalysisProfileVersion = '0.5.0'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$maximumPackBytes = 4MB
$maximumManifestBytes = 16KB
$maximumRulesBytes = 4MB
$createdUtc = [DateTimeOffset]::UtcNow
$expires = $ExpiresUtc.ToUniversalTime()
if ($expires -le $createdUtc -or $expires -gt $createdUtc.AddDays(366)) {
    throw 'ExpiresUtc must be after creation and no more than 366 days in the future.'
}

$outputFullPath = [IO.Path]::GetFullPath($OutputPath)
if ([IO.File]::Exists($outputFullPath)) {
    throw "Output already exists: $outputFullPath"
}

$rules = [IO.File]::ReadAllBytes([IO.Path]::GetFullPath($RulesPath))
if ($rules.Length -eq 0 -or $rules.Length -gt $maximumRulesBytes) {
    throw 'Rules must be non-empty and no larger than 4 MiB.'
}

$strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
$rulesText = $strictUtf8.GetString($rules)
if ($rulesText -match '(?ims)^[\t ]*(?:(?:/\*.*?\*/)[\t ]*)*include(?=[\t ]|")') {
    throw 'YARA include directives are disabled; rules must be self-contained.'
}
$rulesSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($rules))
$manifestObject = [ordered]@{
    schemaVersion = 'dbdr-yara-rule-pack/1'
    packId = $PackId
    version = $Version
    keyId = $KeyId
    createdUtc = $createdUtc.ToString('O', [Globalization.CultureInfo]::InvariantCulture)
    expiresUtc = $expires.ToString('O', [Globalization.CultureInfo]::InvariantCulture)
    analysisProfileVersion = $AnalysisProfileVersion
    rulesSha256 = $rulesSha256
}
$manifest = $strictUtf8.GetBytes(($manifestObject | ConvertTo-Json -Compress))
if ($manifest.Length -gt $maximumManifestBytes) {
    throw 'The generated manifest exceeds 16 KiB.'
}

$magic = $strictUtf8.GetBytes("DBDR-YARA-PACK-V1`0")
$payloadStream = [IO.MemoryStream]::new()
try {
    $payloadWriter = [IO.BinaryWriter]::new($payloadStream, $strictUtf8, $true)
    try {
        $payloadWriter.Write($magic)
        $payloadWriter.Write([int]$manifest.Length)
        $payloadWriter.Write($manifest)
        $payloadWriter.Write([int]$rules.Length)
        $payloadWriter.Write($rules)
        $payloadWriter.Flush()
        $payload = $payloadStream.ToArray()
    }
    finally {
        $payloadWriter.Dispose()
    }
}
finally {
    $payloadStream.Dispose()
}

$ecdsa = [Security.Cryptography.ECDsa]::Create()
try {
    $privateKeyPem = [IO.File]::ReadAllText([IO.Path]::GetFullPath($PrivateKeyPemPath))
    $ecdsa.ImportFromPem($privateKeyPem)
    $privateKeyPem = $null
    $curveOid = ($ecdsa.ExportParameters($false)).Curve.Oid.Value
    if ($ecdsa.KeySize -ne 256 -or $curveOid -ne '1.2.840.10045.3.1.7') {
        throw 'The rule-pack signing key must be ECDSA P-256.'
    }

    $signature = $ecdsa.SignData(
        $payload,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
    if ($signature.Length -ne 64) {
        throw 'The signing provider did not return a 64-byte P1363 signature.'
    }

    $outputDirectory = [IO.Path]::GetDirectoryName($outputFullPath)
    if (-not [string]::IsNullOrWhiteSpace($outputDirectory)) {
        [IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
    }

    $archiveStream = [IO.FileStream]::new(
        $outputFullPath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None)
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $archiveStream,
            [IO.Compression.ZipArchiveMode]::Create,
            $true)
        try {
            foreach ($item in @(
                @{ Name = 'manifest.json'; Bytes = $manifest },
                @{ Name = 'rules.yar'; Bytes = $rules },
                @{ Name = 'signature.p1363'; Bytes = $signature })) {
                $entry = $archive.CreateEntry($item.Name, [IO.Compression.CompressionLevel]::Optimal)
                $entryStream = $entry.Open()
                try {
                    $entryStream.Write($item.Bytes, 0, $item.Bytes.Length)
                }
                finally {
                    $entryStream.Dispose()
                }
            }
        }
        finally {
            $archive.Dispose()
        }
    }
    finally {
        $archiveStream.Dispose()
    }

    $packLength = ([IO.FileInfo]::new($outputFullPath)).Length
    if ($packLength -gt $maximumPackBytes) {
        [IO.File]::Delete($outputFullPath)
        throw 'The generated pack exceeds the 4 MiB client limit; reduce rules.yar.'
    }

    [PSCustomObject]@{
        OutputPath = $outputFullPath
        PackSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($outputFullPath)))
        RulesSha256 = $rulesSha256
        KeyId = $KeyId
        PublicKeySpkiBase64 = [Convert]::ToBase64String($ecdsa.ExportSubjectPublicKeyInfo())
        ExpiresUtc = $expires.ToString('O', [Globalization.CultureInfo]::InvariantCulture)
    }
}
catch {
    if ([IO.File]::Exists($outputFullPath)) {
        [IO.File]::Delete($outputFullPath)
    }

    throw
}
finally {
    $ecdsa.Dispose()
}
