#!/usr/bin/env bash
#
# EU DSS conformance gate for BonniePDF signatures.
#
# Resolves the European Commission's Digital Signature Service from Maven
# Central, compiles the DssValidate helper, and checks that every signed sample
# reaches the PAdES baseline level it claims. This is the SAME script
# (byte-identical) used by both the TypeScript and .NET signing CI, so both
# libraries clear the identical external bar.
#
# Why this exists alongside the pdfsig gate: `pdfsig` proves a signature
# verifies. It says nothing about which PAdES level the signature reaches, and
# the level is the claim the product sells. A document can carry a perfectly
# valid signature and still be PAdES-BASELINE-T when it says LTA.
#
# The sample directory must contain:
#   *.pdf         the signed samples
#   test-ca.pem   the trust anchor they were signed under
#   expected.tsv  filename <TAB> expected-format <TAB> expected-indication
#
# Usage:  validate.sh <dir-of-signed-pdfs>
#
# Requirements: a JDK (java/javac 17+) and Maven on PATH. Both are provided by
# actions/setup-java in CI; locally, install a JDK + Maven.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAMPLE_DIR="${1:?usage: validate.sh <dir-of-signed-pdfs>}"

if ! command -v mvn >/dev/null 2>&1; then
  echo "::error::maven is not installed"
  exit 1
fi

# Resolve dependencies into tools/dss/lib (offline-cached after first run).
if [ ! -d "$HERE/lib" ] || [ -z "$(ls -A "$HERE/lib" 2>/dev/null)" ]; then
  echo "==> Resolving the EU DSS validator from Maven Central..."
  mvn -q -B -f "$HERE/pom.xml" \
    org.apache.maven.plugins:maven-dependency-plugin:3.9.0:copy-dependencies -DoutputDirectory=lib
fi

# Compile once (or when the source is newer than the class).
if [ ! -f "$HERE/DssValidate.class" ] || [ "$HERE/DssValidate.java" -nt "$HERE/DssValidate.class" ]; then
  echo "==> Compiling DssValidate.java..."
  javac -cp "$HERE/lib/*" -d "$HERE" "$HERE/DssValidate.java"
fi

echo "==> Validating $SAMPLE_DIR with EU DSS"
# DSS is chatty at INFO and its warnings are the useful part, so raise the floor.
java -Dorg.slf4j.simpleLogger.defaultLogLevel=warn \
  -cp "$HERE/lib/*:$HERE" DssValidate "$SAMPLE_DIR"
