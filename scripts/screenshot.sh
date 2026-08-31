#!/usr/bin/env bash
#
# Regenerate docs/screenshot.svg from what the tool actually prints.
#
# The output is captured through a pty, so the colours in the image are the
# ones certreader emits rather than a guess at them, and rendered onto a
# character grid so the columns line up whatever monospace font the reader has.
#
# Needs the network: the first panel reads two live hosts.

set -euo pipefail

cd "$(dirname "$0")/.."

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

go build -o "${work}/certreader" .

# a request that does not verify, which is the interesting case to show
cp pkg/cert/testdata/csr_bad_signature.pem "${work}/request.csr"

script -q /dev/null "${work}/certreader" -expiry google.com:443 github.com:443 > "${work}/panel1.txt" 2>/dev/null </dev/null
( cd "${work}" && script -q /dev/null ./certreader request.csr > panel2.txt 2>/dev/null </dev/null )

python3 scripts/render-terminal-svg.py "${work}/panel1.txt" "${work}/panel2.txt" docs/screenshot.svg
