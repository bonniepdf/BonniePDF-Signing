import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

import java.io.File;
import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * EU DSS conformance gate.
 *
 * <p>Usage: {@code DssValidate <sample-dir>}, where the directory holds signed
 * PDFs, the trust anchor as {@code test-ca.pem}, and an {@code expected.tsv} of
 * {@code filename <TAB> expected-format <TAB> expected-indication} lines written
 * by the sample generator.
 *
 * <p>The expectations live with the generator rather than here, because they are
 * a statement about what the library claims to produce; this program only
 * reports whether the European Commission's validator agrees.
 *
 * <p>Validation runs <b>offline</b>: no AIA, OCSP or CRL fetching, and the only
 * trusted certificate is the throwaway CA the samples were signed with.
 * Everything a validator needs must therefore come from inside the document,
 * which is precisely the property the long-term levels exist to provide.
 *
 * <p>Exits 0 only if every file matches its expectation; exits 1 otherwise, so
 * it gates CI. A level silently regressing from LTA to T is the failure this
 * catches, and it is invisible to a signature-only check like {@code pdfsig}.
 */
public final class DssValidate {

    /** One file's expected verdict. */
    private record Expectation(String format, String indication) {}

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: DssValidate <sample-dir>");
            System.exit(2);
        }

        File dir = new File(args[0]);
        File trustAnchor = new File(dir, "test-ca.pem");
        File manifest = new File(dir, "expected.tsv");

        if (!trustAnchor.isFile()) {
            System.err.println("::error::missing trust anchor " + trustAnchor);
            System.exit(2);
        }
        if (!manifest.isFile()) {
            System.err.println("::error::missing expectations " + manifest);
            System.exit(2);
        }

        Map<String, Expectation> expected = readExpectations(manifest);
        if (expected.isEmpty()) {
            System.err.println("::error::expectations file is empty");
            System.exit(2);
        }

        CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
        trusted.addCertificate(DSSUtils.loadCertificate(trustAnchor));

        List<String> rows = new ArrayList<>();
        boolean failed = false;

        for (Map.Entry<String, Expectation> entry : expected.entrySet()) {
            String name = entry.getKey();
            Expectation want = entry.getValue();
            File pdf = new File(dir, name);

            if (!pdf.isFile()) {
                System.out.println("::error::FAIL " + name + "  (file not produced)");
                rows.add(row(name, want, "-", "-", false));
                failed = true;
                continue;
            }

            String format;
            String indication;
            try {
                Reports reports = validate(pdf, trusted);
                SimpleReport simple = reports.getSimpleReport();
                DiagnosticData diagnostic = reports.getDiagnosticData();

                List<SignatureWrapper> signatures = diagnostic.getSignatures();
                if (signatures.isEmpty()) {
                    System.out.println("::error::FAIL " + name + "  (no signature found)");
                    rows.add(row(name, want, "-", "-", false));
                    failed = true;
                    continue;
                }

                String id = signatures.get(0).getId();
                format = String.valueOf(signatures.get(0).getSignatureFormat());
                indication = String.valueOf(simple.getIndication(id));
            } catch (RuntimeException e) {
                System.out.println("::error::FAIL " + name + "  (" + e + ")");
                rows.add(row(name, want, "-", "-", false));
                failed = true;
                continue;
            }

            boolean ok = want.format().equals(format) && want.indication().equals(indication);
            rows.add(row(name, want, format, indication, ok));

            if (ok) {
                System.out.println("PASS  " + name + "  " + format + " / " + indication);
            } else {
                System.out.println("::error::FAIL " + name
                        + "  expected " + want.format() + " / " + want.indication()
                        + " but DSS reported " + format + " / " + indication);
                failed = true;
            }
        }

        writeSummary(rows);

        if (failed) {
            System.err.println("::error::EU DSS validation failed");
            System.exit(1);
        }
        System.out.println("All " + expected.size() + " signed PDFs reached the level they claim.");
    }

    private static Reports validate(File pdf, CommonTrustedCertificateSource trusted) {
        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        verifier.setTrustedCertSources(trusted);
        // Offline on purpose: everything must come from inside the document.
        verifier.setAIASource(null);
        verifier.setOcspSource(null);
        verifier.setCrlSource(null);

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new FileDocument(pdf));
        validator.setCertificateVerifier(verifier);
        return validator.validateDocument();
    }

    private static Map<String, Expectation> readExpectations(File manifest) throws IOException {
        Map<String, Expectation> expected = new LinkedHashMap<>();
        for (String line : Files.readAllLines(manifest.toPath(), StandardCharsets.UTF_8)) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) continue;
            String[] parts = trimmed.split("\t");
            if (parts.length < 3) {
                throw new IOException("malformed expectation line: " + line);
            }
            expected.put(parts[0], new Expectation(parts[1], parts[2]));
        }
        return expected;
    }

    private static String row(String name, Expectation want, String format, String indication, boolean ok) {
        return "| " + name + " | " + want.format() + " | " + format + " | " + indication
                + " | " + (ok ? "PASS" : "**FAIL**") + " |";
    }

    /** Write a Markdown table to the CI run summary, and alongside it on disk. */
    private static void writeSummary(List<String> rows) throws IOException {
        StringBuilder table = new StringBuilder("### EU DSS validation\n\n")
                .append("| File | Expected level | Reported level | Indication | |\n")
                .append("| --- | --- | --- | --- | --- |\n");
        for (String row : rows) table.append(row).append('\n');

        Files.write(new File("dss-summary.md").toPath(), table.toString().getBytes(StandardCharsets.UTF_8));

        String summaryPath = System.getenv("GITHUB_STEP_SUMMARY");
        if (summaryPath != null && !summaryPath.isEmpty()) {
            try (Writer writer = Files.newBufferedWriter(
                    new File(summaryPath).toPath(), StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND)) {
                writer.write(table.toString());
            }
        }
    }
}
