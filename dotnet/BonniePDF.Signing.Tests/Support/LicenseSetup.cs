using System.Runtime.CompilerServices;

namespace BonniePDF.Signing.Tests.Support;

/// <summary>
/// Declares a licence tier for the whole signing test assembly.
/// </summary>
/// <remarks>
/// The signing tests generate real documents with BonniePDF core to sign, and
/// core requires the consuming application to declare which licence applies to
/// it. A loaded test framework counts as a development environment, so without
/// this every test that builds a PDF to sign would throw. The test suite is not
/// production use, so <see cref="LicenseTier.Evaluation"/> is the honest
/// declaration.
/// <para>
/// A module initializer rather than a fixture: it runs before any test in the
/// assembly, including tests in classes that do not opt into a collection.
/// </para>
/// </remarks>
internal static class LicenseSetup
{
    [ModuleInitializer]
    internal static void Initialize()
    {
        BonniePdfLicense.Tier = LicenseTier.Evaluation;
    }
}
