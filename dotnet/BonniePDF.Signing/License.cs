using System;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace BonniePDF.Signing;

/// <summary>Licence edition. <c>Free</c> is the unlicensed/evaluation tier (no signed key).</summary>
public enum LicenseEdition
{
    Free,
    Professional,
    Enterprise,
}

/// <summary>
/// Outcome of verifying a licence key.
/// </summary>
public enum LicenseStatus
{
    /// <summary>Signature verifies and the key is current.</summary>
    Valid,
    /// <summary>Expired, but within the grace window; still usable (warns).</summary>
    Grace,
    /// <summary>Expired beyond the grace window.</summary>
    Expired,
    /// <summary>Malformed or the signature does not verify (forged/corrupt).</summary>
    Invalid,
    /// <summary>The customer id is on the embedded revocation list.</summary>
    Revoked,
    /// <summary>No key was supplied at all (evaluation mode).</summary>
    Unlicensed,
}

/// <summary>Claims carried by a licence key. Minted and signed by the vendor.</summary>
public sealed class LicenseClaims
{
    /// <summary>Customer id (subject). Used for attribution and revocation.</summary>
    [JsonPropertyName("sub")]
    public string Sub { get; set; }

    /// <summary>Licensed edition (<c>free</c>/<c>professional</c>/<c>enterprise</c>).</summary>
    [JsonPropertyName("edition")]
    public string Edition { get; set; }

    /// <summary>Optional seat count (informational; not enforced at runtime).</summary>
    [JsonPropertyName("seats")]
    public int? Seats { get; set; }

    /// <summary>Optional feature flags this licence unlocks.</summary>
    [JsonPropertyName("features")]
    public string[] Features { get; set; }

    /// <summary>Issued-at date (ISO <c>YYYY-MM-DD</c> or full ISO 8601).</summary>
    [JsonPropertyName("iat")]
    public string Iat { get; set; }

    /// <summary>Expiry date (ISO <c>YYYY-MM-DD</c> or full ISO 8601). Absent = perpetual.</summary>
    [JsonPropertyName("exp")]
    public string Exp { get; set; }
}

/// <summary>Result of <see cref="License.Verify"/>.</summary>
public sealed class LicenseVerification
{
    /// <summary>Whether signing may proceed (true for <c>Valid</c> and <c>Grace</c>).</summary>
    public bool Ok { get; init; }

    /// <summary>The verification status.</summary>
    public LicenseStatus Status { get; init; }

    /// <summary>Parsed claims, when the token was well-formed (even if expired/revoked).</summary>
    public LicenseClaims Claims { get; init; }

    /// <summary>Human-readable explanation, suitable for logging.</summary>
    public string Message { get; init; }
}

/// <summary>
/// Offline licence-key verification for the commercial signing add-on.
///
/// A licence key is a short, signed token verified <b>entirely offline</b>
/// against an embedded public key - no licence server, no network call, works
/// air-gapped. The mechanism deters <i>forgery</i> (you cannot mint a valid key
/// without the vendor's private key) while keeping zero-friction
/// setup. It is intentionally <b>not</b> DRM: the package is source-available,
/// so the check can be patched out. The goal is to make the honest path the easy
/// path and any bypass a deliberate, attributable act of circumvention.
///
/// Token format (<c>BPDF1</c>):
/// <c>BPDF1.&lt;base64url(claimsJson)&gt;.&lt;base64url(signature)&gt;</c>.
/// The signature is ECDSA P-256 / SHA-256 (IEEE P1363) over the UTF-8 bytes of
/// <c>BPDF1.&lt;base64url(claimsJson)&gt;</c>. P-256 is used (not Ed25519) so the
/// same token verifies in the .NET BCL and the TypeScript port's Web Crypto.
/// </summary>
public static class License
{
    private const string Prefix = "BPDF1";

    /// <summary>Days a key keeps working after <c>exp</c> before signing is blocked.</summary>
    public const int DefaultGraceDays = 30;

    /// <summary>
    /// Vendor public key (SPKI, base64), used to verify licence signatures.
    ///
    /// PLACEHOLDER - replace with your own key before publishing. Generate a
    /// keypair with <c>openssl genpkey -algorithm EC -pkeyopt
    /// ec_paramgen_curve:P-256</c>, embed the <b>public</b> half here, and keep
    /// the private half offline. The matching private key is intentionally not
    /// committed, so no real key can be minted against this placeholder. Must
    /// match the TypeScript port's <c>LICENSE_PUBLIC_KEY_SPKI</c>.
    /// </summary>
    public const string PublicKeySpki =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdurRtkqh1iLxsOoCJ1yNFV8/dDg0J7TU8zCrtx3C4b+2nbRVzQOb70VNjIWhzPc3mT1ntb3lf9n0vxC1O/1tVQ==";

    /// <summary>
    /// Revoked customer ids. A leaked key keeps working on already-released
    /// versions but dies on upgrade once its <c>sub</c> is listed here.
    /// </summary>
    public static readonly string[] RevokedCustomers = Array.Empty<string>();

    /// <summary>
    /// Global licence key. Set once at startup
    /// (<c>License.Key = "BPDF1.…";</c>) instead of per-call. Lowest precedence
    /// after an explicit <see cref="SignatureSettings.License"/> and the
    /// environment/file fallbacks.
    /// </summary>
    public static string Key { get; set; }

    private static bool _warned;

    /// <summary>Verify a licence token offline against the embedded public key.</summary>
    /// <param name="token">The <c>BPDF1.…</c> key, or null/empty for <c>Unlicensed</c>.</param>
    /// <param name="now">Clock override (for testing). Defaults to <see cref="DateTimeOffset.UtcNow"/>.</param>
    /// <param name="graceDays">Days past <c>exp</c> still allowed.</param>
    /// <param name="publicKeySpki">Public-key override (for testing).</param>
    public static LicenseVerification Verify(string token, DateTimeOffset? now = null, int graceDays = DefaultGraceDays, string publicKeySpki = null)
    {
        DateTimeOffset clock = now ?? DateTimeOffset.UtcNow;

        if (string.IsNullOrWhiteSpace(token))
        {
            return Fail(LicenseStatus.Unlicensed, "no licence key provided", null);
        }

        string[] parts = token.Trim().Split('.');
        if (parts.Length != 3 || parts[0] != Prefix)
        {
            return Fail(LicenseStatus.Invalid, $"malformed licence key (expected \"{Prefix}.<payload>.<signature>\")", null);
        }

        LicenseClaims claims;
        try
        {
            byte[] payload = Base64UrlDecode(parts[1]);
            claims = JsonSerializer.Deserialize<LicenseClaims>(payload);
        }
        catch (Exception ex) when (ex is JsonException or FormatException)
        {
            return Fail(LicenseStatus.Invalid, "licence payload is not valid JSON", null);
        }

        bool verified;
        try
        {
            byte[] signingInput = Encoding.UTF8.GetBytes($"{Prefix}.{parts[1]}");
            byte[] signature = Base64UrlDecode(parts[2]);
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKeySpki ?? PublicKeySpki), out _);
            verified = ecdsa.VerifyData(signingInput, signature, HashAlgorithmName.SHA256);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            return Fail(LicenseStatus.Invalid, "licence signature could not be checked", claims);
        }

        if (!verified)
        {
            return Fail(LicenseStatus.Invalid, "licence signature does not verify (forged or corrupted key)", claims);
        }

        if (!string.IsNullOrEmpty(claims?.Sub) && Array.IndexOf(RevokedCustomers, claims.Sub) >= 0)
        {
            return Fail(LicenseStatus.Revoked, $"licence for \"{claims.Sub}\" has been revoked", claims);
        }

        if (!string.IsNullOrEmpty(claims?.Exp) &&
            DateTimeOffset.TryParse(claims.Exp, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset exp))
        {
            DateTimeOffset grace = exp.AddDays(graceDays);
            if (clock > grace)
            {
                return Fail(LicenseStatus.Expired, $"licence expired on {claims.Exp} (past the {graceDays}-day grace period)", claims);
            }
            if (clock > exp)
            {
                return Pass(LicenseStatus.Grace, $"licence expired on {claims.Exp}; within the {graceDays}-day grace period", claims);
            }
        }

        return Pass(LicenseStatus.Valid, $"licensed to \"{claims?.Sub}\" ({claims?.Edition})", claims);
    }

    /// <summary>
    /// Resolve a licence key from (in order): the explicit argument, the global
    /// <see cref="Key"/>, the <c>BONNIEPDF_LICENSE_KEY</c> environment variable,
    /// then a licence file (<c>BONNIEPDF_LICENSE_FILE</c>, or
    /// <c>bonniepdf.license</c> in the working directory). Returns null if none.
    /// </summary>
    public static string Resolve(string explicitKey)
    {
        if (!string.IsNullOrWhiteSpace(explicitKey)) return explicitKey.Trim();
        if (!string.IsNullOrWhiteSpace(Key)) return Key.Trim();

        string fromEnv = Environment.GetEnvironmentVariable("BONNIEPDF_LICENSE_KEY");
        if (!string.IsNullOrWhiteSpace(fromEnv)) return fromEnv.Trim();

        string explicitFile = Environment.GetEnvironmentVariable("BONNIEPDF_LICENSE_FILE");
        string path = explicitFile ?? "bonniepdf.license";
        try
        {
            if (File.Exists(path)) return File.ReadAllText(path).Trim();
            if (!string.IsNullOrEmpty(explicitFile)) throw new FileNotFoundException("licence file not found", path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Default-path failures are non-fatal; explicit BONNIEPDF_LICENSE_FILE rethrows above.
        }

        return null;
    }

    /// <summary>
    /// Resolve + verify the licence and apply the enforcement policy used by
    /// <see cref="PdfSigner"/>: <c>Valid</c> proceeds; <c>Grace</c> proceeds with
    /// a one-time warning; <c>Invalid</c>/<c>Expired</c>/<c>Revoked</c> throw; and
    /// <c>Unlicensed</c> throws when a licence is required (<paramref name="requireLicense"/>
    /// or env <c>BONNIEPDF_LICENSE_REQUIRE=1</c>), otherwise warns once and runs
    /// in evaluation mode.
    /// </summary>
    public static LicenseVerification Enforce(string explicitKey, bool requireLicense)
    {
        string token = Resolve(explicitKey);
        LicenseVerification result = Verify(token);
        bool required = requireLicense || Environment.GetEnvironmentVariable("BONNIEPDF_LICENSE_REQUIRE") == "1";

        switch (result.Status)
        {
            case LicenseStatus.Valid:
                return result;
            case LicenseStatus.Grace:
                WarnOnce($"BonniePDF.Signing: {result.Message}. Renew your licence to avoid interruption.");
                return result;
            case LicenseStatus.Unlicensed:
                if (required)
                {
                    throw new InvalidOperationException(
                        "BonniePDF.Signing requires a licence key. Set SignatureSettings.License, License.Key, " +
                        "the BONNIEPDF_LICENSE_KEY env var, or a bonniepdf.license file. See LICENSING.md.");
                }
                WarnOnce(
                    "BonniePDF.Signing: no licence key found - running in EVALUATION mode. " +
                    "A paid licence is required for production use. See LICENSING.md.");
                return result;
            default: // Invalid | Expired | Revoked
                throw new InvalidOperationException($"BonniePDF.Signing licence error: {result.Message}. See LICENSING.md.");
        }
    }

    /// <summary>Reset the one-time warning latch. Test-only.</summary>
    public static void ResetWarning() => _warned = false;

    private static void WarnOnce(string message)
    {
        if (_warned) return;
        _warned = true;
        Console.Error.WriteLine(message);
    }

    private static LicenseVerification Fail(LicenseStatus status, string message, LicenseClaims claims) =>
        new() { Ok = false, Status = status, Message = message, Claims = claims };

    private static LicenseVerification Pass(LicenseStatus status, string message, LicenseClaims claims) =>
        new() { Ok = true, Status = status, Message = message, Claims = claims };

    private static byte[] Base64UrlDecode(string input)
    {
        string s = input.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }
}
