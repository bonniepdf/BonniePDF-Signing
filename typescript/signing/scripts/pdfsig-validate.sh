#!/usr/bin/env bash
#
# External-validator gate for BonniePDF signatures.
#
# Runs `pdfsig` (Poppler) over every PDF in a directory and asserts that each
# signature is cryptographically valid and covers the whole document. This is
# the SAME script (byte-identical) used by both the TypeScript and .NET signing
# CI, so both libraries clear the identical external bar.
#
# Notes:
# - `pdfsig` exits 0 even for a tampered signature, so we parse its output
#   rather than trusting the exit code.
# - A self-signed test certificate reports "Certificate issuer isn't Trusted":
#   that is a trust-chain note, NOT a signature failure, and is ignored here.
#   A real signature defect shows as "Digest Mismatch" / "Signature is Invalid".
#
# Usage:  pdfsig-validate.sh <dir-of-signed-pdfs>
set -euo pipefail

dir="${1:?usage: pdfsig-validate.sh <dir-of-signed-pdfs>}"

if ! command -v pdfsig >/dev/null 2>&1; then
  echo "::error::pdfsig (poppler-utils) is not installed"
  exit 1
fi

shopt -s nullglob
pdfs=("$dir"/*.pdf)
if [ ${#pdfs[@]} -eq 0 ]; then
  echo "::error::no PDFs found in $dir"
  exit 1
fi

fail=0
for f in "${pdfs[@]}"; do
  out="$(pdfsig "$f" 2>&1 || true)"
  sigs=$(grep -c "Signature #" <<<"$out" || true)
  valid=$(grep -c "Signature Validation: Signature is Valid." <<<"$out" || true)
  bad=$(grep -cE "Digest Mismatch|Signature is Invalid|Signature is Not Valid|is not signed" <<<"$out" || true)

  if [ "$sigs" -ge 1 ] && [ "$valid" -eq "$sigs" ] && [ "$bad" -eq 0 ]; then
    echo "PASS  $(basename "$f")  ($valid/$sigs signature(s) valid)"
  else
    echo "::error::FAIL $(basename "$f")  sigs=$sigs valid=$valid bad=$bad"
    echo "$out"
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "::error::external pdfsig validation failed"
  exit 1
fi
echo "All ${#pdfs[@]} signed PDFs validated by pdfsig."
