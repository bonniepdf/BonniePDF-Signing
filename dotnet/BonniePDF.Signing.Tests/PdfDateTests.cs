using System;
using System.Globalization;
using BonniePDF.Signing.Pdf;
using Xunit;

namespace BonniePDF.Signing.Tests;

/// <summary>
/// The signing time in /M, the DSS /TU entry and the default appearance text
/// is file syntax, so it must not follow the culture of the signing machine.
/// </summary>
public class PdfDateTests
{
    [Theory]
    [InlineData("th-TH")] // Thai Buddhist calendar: years run 543 ahead
    [InlineData("fi-FI")]
    [InlineData("ar-SA")] // Um Al-Qura (Hijri) calendar
    public void FormatsInTheInvariantCultureWhateverTheCurrentOne(string culture)
    {
        CultureInfo previous = CultureInfo.CurrentCulture;
        CultureInfo.CurrentCulture = new CultureInfo(culture);
        try
        {
            string date = PdfIncrementalUpdate.PdfDate(new DateTimeOffset(2026, 9, 23, 14, 5, 9, TimeSpan.Zero));
            Assert.Equal("D:20260923140509+00'00'", date);
        }
        finally
        {
            CultureInfo.CurrentCulture = previous;
        }
    }
}
