using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using BonniePDF.Signing.Cms;
using Xunit;

namespace BonniePDF.Signing.Tests;

public class CmsBuilderTests
{
    [Fact]
    public async Task RecordsTheSigningTimeItIsGivenNotTheClock()
    {
        // The signer writes /M first and builds the envelope afterwards. Reading
        // the clock a second time here could land on a different second from /M,
        // leaving two claims about when the document was signed that disagree.
        (string certPem, string keyPem) = TestCerts.Rsa();
        var settings = new SignatureSettings { CertificatePem = certPem, PrivateKeyPem = keyPem };
        using X509Certificate2 cert = CertificateLoader.Load(settings);
        var written = new DateTimeOffset(2020, 1, 2, 3, 4, 5, TimeSpan.Zero);

        CmsBuilder.CmsResult result = await CmsBuilder.BuildAsync(
            [1, 2, 3], cert, [], settings, written, CancellationToken.None);

        var cms = new SignedCms(new ContentInfo([1, 2, 3]), detached: true);
        cms.Decode(result.Cms);
        Pkcs9SigningTime? signingTime = null;
        foreach (CryptographicAttributeObject attribute in cms.SignerInfos[0].SignedAttributes)
        {
            if (attribute.Values[0] is Pkcs9SigningTime time) signingTime = time;
        }
        Assert.NotNull(signingTime);
        Assert.Equal(written.UtcDateTime, signingTime!.SigningTime);
    }
}
