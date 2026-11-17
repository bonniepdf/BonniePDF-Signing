using System.Globalization;
using System.Text;
using BonniePDF.Signing.SampleGen.Demos;
using Xunit;

namespace BonniePDF.Signing.Tests;

public sealed class DemoTests : IDisposable
{
    private readonly DemoPki _pki = new();

    public void Dispose() => _pki.Dispose();

    private static string Latin1(byte[] bytes) => Encoding.Latin1.GetString(bytes);

    private static string Number(double value) => value.ToString(CultureInfo.InvariantCulture);

    /// <summary>The box's two corners, lower-left then upper-right, as a PDF /Rect.</summary>
    private static string PdfRect(double[] rect) =>
        $"/Rect [{Number(rect[0])} {Number(rect[1])} {Number(rect[0] + rect[2])} {Number(rect[1] + rect[3])}]";

    [Fact]
    public void TheSignedAgreementIsSignedOverTheBoxTheLayoutReserved()
    {
        (_, _, double[] rect) = SignedAgreementDemo.BuildAgreement();
        string signed = Latin1(SignedAgreementDemo.BuildSigned(_pki));

        Assert.Contains(PdfRect(rect), signed, StringComparison.Ordinal);
        Assert.Contains($"/BBox [0 0 {Number(rect[2])} {Number(rect[3])}]", signed, StringComparison.Ordinal);
    }

    [Fact]
    public void TheSignatureBoxStaysOnThePage()
    {
        (_, _, double[] rect) = SignedAgreementDemo.BuildAgreement();

        Assert.True(rect[0] >= 0 && rect[1] >= 0);
        Assert.True(rect[0] + rect[2] <= 595.28);
        Assert.True(rect[1] + rect[3] <= 841.89);
    }

    [Fact]
    public void TheSignedAgreementIsPadesBaselineBWithTheSignerNamed()
    {
        string signed = Latin1(SignedAgreementDemo.BuildSigned(_pki));

        Assert.Contains("/SubFilter /ETSI.CAdES.detached", signed, StringComparison.Ordinal);
        Assert.Contains("/Name (Alex Supplier)", signed, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheSealedCertificateIsSealedOverTheBoxTheLayoutReserved()
    {
        (_, _, double[] rect) = SealedCertificateDemo.BuildCertificate();
        string sealedPdf = Latin1(await SealedCertificateDemo.BuildSealedAsync(_pki));

        Assert.Contains(PdfRect(rect), sealedPdf, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheSealedCertificateCarriesTheValidationDataThatLetsItVerifyOffline()
    {
        string sealedPdf = Latin1(await SealedCertificateDemo.BuildSealedAsync(_pki));

        Assert.Contains("/DSS", sealedPdf, StringComparison.Ordinal);
        Assert.Contains("/SubFilter /ETSI.CAdES.detached", sealedPdf, StringComparison.Ordinal);
    }
}
