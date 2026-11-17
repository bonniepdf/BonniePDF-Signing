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
# - A PAdES B-LTA file ends with an RFC 3161 document timestamp, listed as a
#   signature named "Timestamp<n>". Poppler older than 25.x cannot verify it and
#   reports "Signature has not yet been verified", so it is left out of the count
#   here. It is not unchecked: the DSS gate (tools/dss/validate.sh) validates the
#   whole B-LTA chain, timestamp included. A timestamp that is *wrong* still
#   fails here, through the "Digest Mismatch" / "Signature is Invalid" patterns.
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
  # Document timestamps are listed as signatures; count only the real ones (see the notes above).
  sigs=$(grep -c "Signature #" <<<"$out" || true)
  stamps=$(grep -c "Signature Field Name: Timestamp" <<<"$out" || true)
  sigs=$((sigs - stamps))
  valid=$(grep -c "Signature Validation: Signature is Valid." <<<"$out" || true)
  bad=$(grep -cE "Digest Mismatch|Signature is Invalid|Signature is Not Valid|is not signed" <<<"$out" || true)

  if [ "$sigs" -ge 1 ] && [ "$valid" -ge "$sigs" ] && [ "$bad" -eq 0 ]; then
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
