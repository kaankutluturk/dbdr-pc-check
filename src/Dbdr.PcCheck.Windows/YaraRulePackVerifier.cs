using System.Buffers.Binary;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Dbdr.PcCheck.Core;

namespace Dbdr.PcCheck.Windows;

public sealed record YaraRulePackManifest(
    string SchemaVersion,
    string PackId,
    string Version,
    string KeyId,
    DateTimeOffset CreatedUtc,
    DateTimeOffset ExpiresUtc,
    string AnalysisProfileVersion,
    string RulesSha256);

public sealed record VerifiedYaraRulePack(
    YaraRulePackManifest Manifest,
    byte[] Rules,
    string RuleSetId,
    string RulesSha256);

public static class YaraRulePackVerifier
{
    public const string SchemaVersion = "dbdr-yara-rule-pack/1";
    public const long MaximumPackBytes = 4L * 1024 * 1024;
    public const int MaximumManifestBytes = 16 * 1024;
    public const int MaximumRulesBytes = 4 * 1024 * 1024;
    public const int P1363SignatureBytes = 64;
    public const string RuleSetPrefix = "signed:";
    private const string TrustMetadataPrefix = "DbdrYaraRulePackPublicKey.";
    private const string NistP256Oid = "1.2.840.10045.3.1.7";
    private static readonly byte[] SignedPayloadMagic = "DBDR-YARA-PACK-V1\0"u8.ToArray();
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    private static readonly JsonSerializerOptions ManifestOptions = new()
    {
        PropertyNameCaseInsensitive = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        MaxDepth = 8,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    public static VerifiedYaraRulePack VerifyDefault(string packPath) =>
        Verify(packPath, LoadEmbeddedTrustKeys(), DateTimeOffset.UtcNow);

    public static VerifiedYaraRulePack Verify(
        string packPath,
        IReadOnlyDictionary<string, string> trustedPublicKeys,
        DateTimeOffset verificationTimeUtc)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(packPath);
        ArgumentNullException.ThrowIfNull(trustedPublicKeys);
        var file = new FileInfo(Path.GetFullPath(packPath));
        file.Refresh();
        if (!file.Exists)
        {
            throw new FileNotFoundException("The signed YARA rule pack was not found.", file.FullName);
        }

        if (file.Length is <= 0 or > MaximumPackBytes)
        {
            throw new InvalidDataException("The signed YARA rule pack is empty or exceeds the 4 MiB limit.");
        }

        using var stream = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: false);
        var entries = archive.Entries.ToArray();
        var expectedNames = new HashSet<string>(StringComparer.Ordinal)
        {
            "manifest.json",
            "rules.yar",
            "signature.p1363",
        };
        if (entries.Length != expectedNames.Count
            || entries.Any(entry => !expectedNames.Remove(entry.FullName))
            || expectedNames.Count != 0)
        {
            throw new InvalidDataException("The signed YARA rule pack must contain only manifest.json, rules.yar and signature.p1363 at its root.");
        }

        var manifestBytes = ReadEntry(archive.GetEntry("manifest.json")!, MaximumManifestBytes);
        var rulesBytes = ReadEntry(archive.GetEntry("rules.yar")!, MaximumRulesBytes);
        var signature = ReadEntry(archive.GetEntry("signature.p1363")!, P1363SignatureBytes);
        if (signature.Length != P1363SignatureBytes)
        {
            throw new InvalidDataException("The signed YARA rule pack signature has an invalid length.");
        }

        YaraRulePackManifest manifest;
        try
        {
            ValidateManifestShape(manifestBytes);
            manifest = JsonSerializer.Deserialize<YaraRulePackManifest>(manifestBytes, ManifestOptions)
                ?? throw new InvalidDataException("The signed YARA rule pack manifest is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The signed YARA rule pack manifest is invalid.", exception);
        }

        ValidateManifest(manifest, verificationTimeUtc);
        ValidateSelfContainedRules(rulesBytes);
        var calculatedRulesHash = SHA256.HashData(rulesBytes);
        byte[] manifestRulesHash;
        try
        {
            manifestRulesHash = Convert.FromHexString(manifest.RulesSha256);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException("The signed YARA rule pack rules hash is invalid.", exception);
        }

        if (manifestRulesHash.Length != calculatedRulesHash.Length
            || !CryptographicOperations.FixedTimeEquals(manifestRulesHash, calculatedRulesHash))
        {
            throw new InvalidDataException("The signed YARA rule pack rules hash does not match rules.yar.");
        }

        if (!trustedPublicKeys.TryGetValue(manifest.KeyId, out var publicKeyBase64)
            || string.IsNullOrWhiteSpace(publicKeyBase64))
        {
            throw new InvalidDataException($"The signed YARA rule pack key is not trusted: {manifest.KeyId}");
        }

        using var ecdsa = ImportTrustedPublicKey(manifest.KeyId, publicKeyBase64);

        var signedPayload = CreateSignedPayload(manifestBytes, rulesBytes);
        bool validSignature;
        try
        {
            validSignature = ecdsa.VerifyData(
                signedPayload,
                signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException("The signed YARA rule pack signature is invalid.", exception);
        }

        if (!validSignature)
        {
            throw new InvalidDataException("The signed YARA rule pack signature is invalid.");
        }

        var hash = Convert.ToHexString(calculatedRulesHash);
        return new VerifiedYaraRulePack(
            manifest,
            rulesBytes,
            $"{RuleSetPrefix}{manifest.PackId}@{manifest.Version}",
            hash);
    }

    public static byte[] CreateSignedPayload(
        ReadOnlySpan<byte> manifestBytes,
        ReadOnlySpan<byte> rulesBytes)
    {
        var payloadLength = checked(SignedPayloadMagic.Length + sizeof(int) + manifestBytes.Length + sizeof(int) + rulesBytes.Length);
        var payload = new byte[payloadLength];
        var offset = 0;
        SignedPayloadMagic.AsSpan().CopyTo(payload.AsSpan(offset));
        offset += SignedPayloadMagic.Length;
        BinaryPrimitives.WriteInt32LittleEndian(payload.AsSpan(offset, sizeof(int)), manifestBytes.Length);
        offset += sizeof(int);
        manifestBytes.CopyTo(payload.AsSpan(offset, manifestBytes.Length));
        offset += manifestBytes.Length;
        BinaryPrimitives.WriteInt32LittleEndian(payload.AsSpan(offset, sizeof(int)), rulesBytes.Length);
        offset += sizeof(int);
        rulesBytes.CopyTo(payload.AsSpan(offset, rulesBytes.Length));
        return payload;
    }

    public static IReadOnlyDictionary<string, string> LoadEmbeddedTrustKeys()
    {
        var keys = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var metadata in typeof(YaraRulePackVerifier).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>())
        {
            if (!metadata.Key.StartsWith(TrustMetadataPrefix, StringComparison.Ordinal))
            {
                continue;
            }

            var keyId = metadata.Key[TrustMetadataPrefix.Length..];
            if (!IsSafeIdentifier(keyId) || string.IsNullOrWhiteSpace(metadata.Value))
            {
                throw new InvalidDataException("The build contains an invalid YARA trust-key declaration.");
            }

            using var key = ImportTrustedPublicKey(keyId, metadata.Value);
            if (!keys.TryAdd(keyId, metadata.Value))
            {
                throw new InvalidDataException($"The build contains a duplicate YARA trust key identifier: {keyId}");
            }
        }

        return keys;
    }

    public static void ValidateSelfContainedRules(ReadOnlySpan<byte> rulesBytes)
    {
        string text;
        try
        {
            text = StrictUtf8.GetString(rulesBytes);
        }
        catch (DecoderFallbackException exception)
        {
            throw new InvalidDataException("YARA rules must be valid UTF-8.", exception);
        }

        var withoutComments = RemoveComments(text);
        foreach (var line in withoutComments.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = line.TrimStart();
            if (candidate.StartsWith("include", StringComparison.OrdinalIgnoreCase)
                && (candidate.Length == "include".Length
                    || char.IsWhiteSpace(candidate["include".Length])
                    || candidate["include".Length] == '"'))
            {
                throw new InvalidDataException("YARA include directives are disabled; rule packs must be self-contained.");
            }
        }
    }

    private static void ValidateManifest(YaraRulePackManifest manifest, DateTimeOffset verificationTimeUtc)
    {
        if (!string.Equals(manifest.SchemaVersion, SchemaVersion, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"Unsupported signed YARA rule pack schema: {manifest.SchemaVersion}");
        }

        if (!IsSafeIdentifier(manifest.PackId) || !IsSafeIdentifier(manifest.KeyId))
        {
            throw new InvalidDataException("The signed YARA rule pack contains an invalid pack or key identifier.");
        }

        if (!IsSemanticVersion(manifest.Version))
        {
            throw new InvalidDataException("The signed YARA rule pack version must use numeric major.minor.patch form.");
        }

        if (!string.Equals(
                manifest.AnalysisProfileVersion,
                EvidenceAnalyzer.AnalysisProfileVersion,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"The signed YARA rule pack targets analysis profile {manifest.AnalysisProfileVersion}; this build uses {EvidenceAnalyzer.AnalysisProfileVersion}.");
        }

        if (manifest.CreatedUtc.Offset != TimeSpan.Zero
            || manifest.ExpiresUtc.Offset != TimeSpan.Zero
            || manifest.CreatedUtc > verificationTimeUtc.AddMinutes(5)
            || manifest.ExpiresUtc <= manifest.CreatedUtc
            || manifest.ExpiresUtc > manifest.CreatedUtc.AddDays(366)
            || verificationTimeUtc >= manifest.ExpiresUtc)
        {
            throw new InvalidDataException("The signed YARA rule pack is not currently within its permitted validity interval.");
        }

        if (string.IsNullOrWhiteSpace(manifest.RulesSha256)
            || manifest.RulesSha256.Length != 64
            || manifest.RulesSha256.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new InvalidDataException("The signed YARA rule pack rules hash is invalid.");
        }
    }

    private static void ValidateManifestShape(byte[] manifestBytes)
    {
        using var document = JsonDocument.Parse(manifestBytes, new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = ManifestOptions.MaxDepth,
        });
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException("The signed YARA rule pack manifest root must be an object.");
        }

        var requiredNames = new HashSet<string>(StringComparer.Ordinal)
        {
            "schemaVersion",
            "packId",
            "version",
            "keyId",
            "createdUtc",
            "expiresUtc",
            "analysisProfileVersion",
            "rulesSha256",
        };
        foreach (var property in document.RootElement.EnumerateObject())
        {
            if (!requiredNames.Remove(property.Name))
            {
                throw new JsonException($"The signed YARA rule pack manifest has an unexpected or duplicate field: {property.Name}");
            }
        }

        if (requiredNames.Count != 0)
        {
            throw new JsonException("The signed YARA rule pack manifest is missing one or more required fields.");
        }
    }

    private static byte[] ReadEntry(ZipArchiveEntry entry, int maximumBytes)
    {
        if (entry.FullName.Contains('/')
            || entry.FullName.Contains('\\')
            || entry.Length < 0
            || entry.Length > maximumBytes)
        {
            throw new InvalidDataException($"Signed YARA rule pack entry is unsafe or oversized: {entry.FullName}");
        }

        using var input = entry.Open();
        using var output = new MemoryStream(capacity: checked((int)entry.Length));
        var buffer = new byte[64 * 1024];
        while (true)
        {
            var read = input.Read(buffer, 0, buffer.Length);
            if (read == 0)
            {
                break;
            }

            if (output.Length + read > maximumBytes)
            {
                throw new InvalidDataException($"Signed YARA rule pack entry exceeded its limit: {entry.FullName}");
            }

            output.Write(buffer, 0, read);
        }

        return output.ToArray();
    }

    private static ECDsa ImportTrustedPublicKey(string keyId, string publicKeyBase64)
    {
        byte[] publicKey;
        try
        {
            publicKey = Convert.FromBase64String(publicKeyBase64);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException($"The embedded YARA trust key is invalid: {keyId}", exception);
        }

        var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportSubjectPublicKeyInfo(publicKey, out var bytesRead);
            var parameters = ecdsa.ExportParameters(includePrivateParameters: false);
            if (bytesRead != publicKey.Length
                || ecdsa.KeySize != 256
                || !string.Equals(
                    parameters.Curve.Oid.Value,
                    NistP256Oid,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException($"The embedded YARA trust key is not an ECDSA P-256 key: {keyId}");
            }

            return ecdsa;
        }
        catch (CryptographicException exception)
        {
            ecdsa.Dispose();
            throw new InvalidDataException($"The embedded YARA trust key is invalid: {keyId}", exception);
        }
        catch
        {
            ecdsa.Dispose();
            throw;
        }
    }

    private static string RemoveComments(string text)
    {
        var output = new StringBuilder(text.Length);
        var inBlockComment = false;
        var inLineComment = false;
        var inQuotedString = false;
        var escaped = false;

        for (var index = 0; index < text.Length; index++)
        {
            var character = text[index];
            var next = index + 1 < text.Length ? text[index + 1] : '\0';

            if (inLineComment)
            {
                if (character is '\r' or '\n')
                {
                    inLineComment = false;
                    output.Append(character);
                }

                continue;
            }

            if (inBlockComment)
            {
                if (character == '*' && next == '/')
                {
                    inBlockComment = false;
                    output.Append(' ');
                    index++;
                }
                else if (character is '\r' or '\n')
                {
                    output.Append(character);
                }

                continue;
            }

            if (inQuotedString)
            {
                output.Append(character);
                if (escaped)
                {
                    escaped = false;
                }
                else if (character == '\\')
                {
                    escaped = true;
                }
                else if (character == '"')
                {
                    inQuotedString = false;
                }

                continue;
            }

            if (character == '/' && next == '/')
            {
                inLineComment = true;
                index++;
                continue;
            }

            if (character == '/' && next == '*')
            {
                inBlockComment = true;
                index++;
                continue;
            }

            output.Append(character);
            if (character == '"')
            {
                inQuotedString = true;
            }
        }

        return output.ToString();
    }

    private static bool IsSafeIdentifier(string? value) =>
        !string.IsNullOrWhiteSpace(value)
        && value.Length <= 64
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');

    private static bool IsSemanticVersion(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var parts = value.Split('.');
        return parts.Length == 3
            && parts.All(part => part.Length > 0
                && int.TryParse(part, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out _));
    }
}
