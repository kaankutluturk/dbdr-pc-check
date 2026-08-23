using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Dbdr.PcCheck.Windows;

internal sealed record AuthenticodeEvidence(
    string Status,
    string VerificationMode,
    string? SignerSubject,
    string? SignerIssuer,
    string? SignerThumbprint,
    string? SignerNotBeforeUtc,
    string? SignerNotAfterUtc);

internal static class AuthenticodeVerifier
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    private const uint WtdUiNone = 2;
    private const uint WtdRevokeNone = 0;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionIgnore = 0;
    private const uint WtdCacheOnlyUrlRetrieval = 0x00001000;

    private const int ErrorSuccess = 0;
    private const int TrustENoSignature = unchecked((int)0x800B0100);
    private const int TrustESubjectNotTrusted = unchecked((int)0x800B0004);
    private const int TrustEExplicitDistrust = unchecked((int)0x800B0111);
    private const int CertEUntrustedRoot = unchecked((int)0x800B0109);
    private const int CertEExpired = unchecked((int)0x800B0101);

    public static AuthenticodeEvidence Inspect(string filePath)
    {
        var filePathPointer = IntPtr.Zero;
        var fileInfoPointer = IntPtr.Zero;

        try
        {
            filePathPointer = Marshal.StringToCoTaskMemUni(filePath);
            var fileInfo = new WinTrustFileInfo
            {
                StructSize = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
                FilePath = filePathPointer,
            };

            fileInfoPointer = Marshal.AllocCoTaskMem(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, fDeleteOld: false);

            var trustData = new WinTrustData
            {
                StructSize = (uint)Marshal.SizeOf<WinTrustData>(),
                UiChoice = WtdUiNone,
                RevocationChecks = WtdRevokeNone,
                UnionChoice = WtdChoiceFile,
                File = fileInfoPointer,
                StateAction = WtdStateActionIgnore,
                ProviderFlags = WtdCacheOnlyUrlRetrieval,
            };

            var action = GenericVerifyV2;
            var status = WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);
            var normalizedStatus = status switch
            {
                ErrorSuccess => "valid",
                TrustENoSignature => "unsigned",
                TrustESubjectNotTrusted => "signed-subject-not-trusted",
                TrustEExplicitDistrust => "signed-explicitly-distrusted",
                CertEUntrustedRoot => "signed-untrusted-root",
                CertEExpired => "signed-certificate-expired",
                _ => $"verification-error-0x{status:X8}",
            };
            return WithEmbeddedSignerMetadata(normalizedStatus, filePath);
        }
        catch (Exception exception) when (exception is ArgumentException or ExternalException)
        {
            return Empty($"unavailable-{exception.GetType().Name}");
        }
        finally
        {
            if (fileInfoPointer != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(fileInfoPointer);
            }

            if (filePathPointer != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(filePathPointer);
            }
        }
    }

    private static AuthenticodeEvidence WithEmbeddedSignerMetadata(string status, string filePath)
    {
        try
        {
            // The BCL has no X509CertificateLoader API that extracts an embedded signer from a PE.
            // Use the signed-file bridge only for extraction, then load the exported DER with the
            // supported loader API. Trust is determined separately by WinVerifyTrust above.
#pragma warning disable SYSLIB0057
            using var certificate = X509Certificate.CreateFromSignedFile(filePath);
#pragma warning restore SYSLIB0057
            using var certificate2 = X509CertificateLoader.LoadCertificate(
                certificate.Export(X509ContentType.Cert));
            return new AuthenticodeEvidence(
                status,
                "WinVerifyTrust Generic Verify V2; cache-only URL retrieval; revocation checks disabled",
                certificate2.GetNameInfo(X509NameType.SimpleName, forIssuer: false),
                certificate2.GetNameInfo(X509NameType.SimpleName, forIssuer: true),
                certificate2.Thumbprint,
                certificate2.NotBefore.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture),
                certificate2.NotAfter.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture));
        }
        catch (CryptographicException)
        {
            return Empty(status);
        }
    }

    private static AuthenticodeEvidence Empty(string status) => new(
        status,
        "WinVerifyTrust Generic Verify V2; cache-only URL retrieval; revocation checks disabled",
        null,
        null,
        null,
        null,
        null);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int WinVerifyTrust(
        IntPtr windowHandle,
        ref Guid actionId,
        ref WinTrustData trustData);

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfo
    {
        public uint StructSize;
        public IntPtr FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint StructSize;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr File;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;
    }
}
