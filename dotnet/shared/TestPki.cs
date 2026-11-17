using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using BonniePDF.Signing.Asn1;

namespace BonniePDF.Signing.TestSupport;

/// <summary>
/// A throwaway public-key infrastructure, built at test time.
/// </summary>
/// <remarks>
/// The signing package must never ship committed private keys, so every
/// certificate, responder and authority the long-term-validation tests need is
/// generated here, in-process, and lives only as long as the test run.
/// <para>
/// It is a real PKI, not a set of stubs: the certificates carry the extensions
/// the collector reads, the timestamp tokens are RFC 3161 TimeStampTokens signed
/// by a TSA key, and the OCSP responses are signed BasicOCSPResponses. That
/// matters - a test that fed the implementation handmade DER would prove only
/// that our own parser agrees with our own writer.
/// </para>
/// <para>
/// Compiled into both the test project and the sample generator, so the CI
/// validation gate signs with exactly the PKI the tests assert against.
/// </para>
/// <para>Mirrors typescript/signing/tests/helpers/pki.ts.</para>
/// </remarks>
internal static class TestPki
{
    public const string TstInfoOid = "1.2.840.113549.1.9.16.1.4";
    public const string BasicOcspResponseOid = "1.3.6.1.5.5.7.48.1.1";
    private const string Sha256WithRsaOid = "1.2.840.113549.1.1.11";
    private const string TsaPolicyOid = "1.3.6.1.4.1.13762.3";

    /// <summary>A certificate and the key that signs with it.</summary>
    internal sealed class Identity : IDisposable
    {
        public X509Certificate2 Certificate { get; init; }

        public RSA Key { get; init; }

        public byte[] CertDer => Certificate.RawData;

        public string CertPem => new(PemEncoding.Write("CERTIFICATE", Certificate.RawData));

        public string KeyPem => new(PemEncoding.Write("PRIVATE KEY", Key.ExportPkcs8PrivateKey()));

        public void Dispose()
        {
            Certificate?.Dispose();
            Key?.Dispose();
        }
    }

    /// <summary>An AuthorityInfoAccess extension naming an OCSP responder.</summary>
    public static X509Extension AiaOcsp(string url)
    {
        byte[] description = Der.Sequence(
            Der.Oid(CertificateExtensionsOids.Ocsp),
            Der.Tlv(0x86, Encoding.ASCII.GetBytes(url)));
        return new X509Extension(CertificateExtensionsOids.Aia, Der.Sequence(description), critical: false);
    }

    /// <summary>A CRLDistributionPoints extension naming one HTTP distribution point.</summary>
    public static X509Extension CrlDistributionPoint(string url)
    {
        byte[] fullName = Der.ContextConstructed(0, Der.Tlv(0x86, Encoding.ASCII.GetBytes(url)));
        byte[] distributionPoint = Der.Sequence(Der.ContextConstructed(0, fullName));
        return new X509Extension(CertificateExtensionsOids.Cdp, Der.Sequence(distributionPoint), critical: false);
    }

    /// <summary>Issue a self-signed certificate authority.</summary>
    public static Identity IssueCa(string subject)
    {
        RSA key = RSA.Create(2048);
        var request = new CertificateRequest($"CN={subject}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        X509Certificate2 cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));
        return new Identity { Certificate = cert, Key = key };
    }

    /// <summary>Issue a leaf certificate under <paramref name="issuer"/>.</summary>
    public static Identity Issue(string subject, Identity issuer, params X509Extension[] extensions)
    {
        RSA key = RSA.Create(2048);
        var request = new CertificateRequest($"CN={subject}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        foreach (X509Extension extension in extensions) request.CertificateExtensions.Add(extension);

        var serial = new byte[8];
        RandomNumberGenerator.Fill(serial);
        serial[0] &= 0x7f;

        using X509Certificate2 unsigned = request.Create(
            issuer.Certificate, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2), serial);

        return new Identity { Certificate = X509Certificate2.CreateFromPem(
            new string(PemEncoding.Write("CERTIFICATE", unsigned.RawData))), Key = key };
    }

    /// <summary>OIDs the test extensions use, spelled once.</summary>
    internal static class CertificateExtensionsOids
    {
        public const string Aia = "1.3.6.1.5.5.7.1.1";
        public const string Cdp = "2.5.29.31";
        public const string Ocsp = "1.3.6.1.5.5.7.48.1";
    }

    /// <summary>A test TSA: answers TimeStampReqs with real signed tokens.</summary>
    internal sealed class TestTsa
    {
        private readonly Identity _identity;
        private int _serial = 1;

        /// <summary>Imprints this authority has been asked to stamp, in order.</summary>
        public List<byte[]> Imprints { get; } = [];

        public TestTsa(Identity identity) => _identity = identity;

        /// <summary>Handle a DER TimeStampReq and return a DER TimeStampResp.</summary>
        public byte[] Respond(byte[] request)
        {
            Der.Node root = Der.Read(request, 0);
            List<Der.Node> children = Der.Children(request, root);
            Der.Node messageImprint = children[1];
            List<Der.Node> imprintParts = Der.Children(request, messageImprint);
            Imprints.Add(Der.Content(request, imprintParts[1]));

            byte[] tstInfo = Der.Sequence(
                Der.IntegerSmall(1),
                Der.Oid(TsaPolicyOid),
                Der.NodeBytes(request, messageImprint),
                Der.IntegerSmall(_serial++),
                Der.GeneralizedTime(DateTimeOffset.UtcNow));

            var contentInfo = new ContentInfo(new Oid(TstInfoOid), tstInfo);
            using X509Certificate2 tsaCert = SigningCertificate();
            var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, tsaCert)
            {
                IncludeOption = X509IncludeOption.EndCertOnly,
            };
            // RFC 3161 §2.4.1: the token's SignerInfo must carry an ESS
            // signing-certificate attribute binding the token to the TSA's
            // certificate. Without it a validator discards the token outright,
            // so a test authority that omits it would quietly certify tokens no
            // real validator would accept.
            signer.SignedAttributes.Add(BonniePDF.Signing.Cms.SigningCertificateV2.Build(tsaCert));

            var cms = new SignedCms(contentInfo, detached: false);
            cms.ComputeSignature(signer, silent: true);

            return Der.Sequence(Der.Sequence(Der.IntegerSmall(0)), cms.Encode());
        }

        private X509Certificate2 SigningCertificate() =>
            X509Certificate2.CreateFromPem(_identity.CertPem, _identity.KeyPem);
    }

    /// <summary>A test OCSP responder that answers "good" for everything it is asked.</summary>
    internal sealed class TestOcspResponder
    {
        private readonly Identity _identity;

        /// <summary>Requests this responder has served.</summary>
        public int Requests { get; private set; }

        public TestOcspResponder(Identity identity) => _identity = identity;

        /// <summary>Handle a DER OCSPRequest and return a DER OCSPResponse.</summary>
        public byte[] Respond(byte[] request)
        {
            Requests++;

            // OCSPRequest > tbsRequest > requestList > Request > reqCert (CertID)
            Der.Node root = Der.Read(request, 0);
            Der.Node tbsRequest = Der.Children(request, root)[0];
            List<Der.Node> tbsChildren = Der.Children(request, tbsRequest);
            Der.Node requestList = tbsChildren[^1];
            Der.Node first = Der.Children(request, requestList)[0];
            Der.Node certId = Der.Children(request, first)[0];

            byte[] singleResponse = Der.Sequence(
                Der.NodeBytes(request, certId),
                Der.Tlv(0x80, []), // certStatus: good [0] IMPLICIT NULL
                Der.GeneralizedTime(DateTimeOffset.UtcNow));

            // ResponderID ::= CHOICE { byName [1] Name, byKey [2] KeyHash }.
            // Name is itself a CHOICE, so [1] is EXPLICIT: the whole Name TLV
            // goes inside the tag, not its content. Tagging it implicitly
            // produces DER that decodes as "unexpected explicit encoding" and
            // is discarded outright by a real validator.
            byte[] subject = CertificateExtensions.ExtractSubject(_identity.CertDer);

            byte[] responseData = Der.Sequence(
                Der.ContextConstructed(0, Der.IntegerSmall(0)),
                Der.ContextConstructed(1, subject), // responderID byName (EXPLICIT)
                Der.GeneralizedTime(DateTimeOffset.UtcNow),
                Der.Sequence(singleResponse));

            byte[] signature = _identity.Key.SignData(
                responseData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            byte[] basic = Der.Sequence(
                responseData,
                Der.Sequence(Der.Oid(Sha256WithRsaOid), Der.Null()),
                BitString(signature),
                Der.ContextConstructed(0, Der.Sequence(_identity.CertDer)));

            return Der.Sequence(
                Der.Enumerated(0),
                Der.ContextConstructed(0, Der.Sequence(Der.Oid(BasicOcspResponseOid), Der.OctetString(basic))));
        }

        private static byte[] BitString(byte[] value)
        {
            var withUnused = new byte[value.Length + 1];
            Buffer.BlockCopy(value, 0, withUnused, 1, value.Length);
            return Der.Tlv(0x03, withUnused);
        }
    }
}
