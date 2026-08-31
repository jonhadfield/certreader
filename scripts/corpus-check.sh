#!/usr/bin/env bash
#
# Run the corpus check over every certificate this machine can find, rather
# than only the fixtures in the repository.
#
# The unit tests compare known certificates against known output, so they cover
# the cases somebody thought to write down. This asks what has to hold for any
# certificate at all — that the output is text a terminal can print, and that
# the json parses — and puts that question to a few hundred real ones. The
# awkward encodings nobody would think to invent are already out there in the
# trust stores.
#
#   scripts/corpus-check.sh                          the system trust store
#   scripts/corpus-check.sh bundle.pem other.pem     and these as well
#
# Certificates are copied to a temporary directory and removed on exit. Nothing
# is sent anywhere.

set -euo pipefail

corpus="$(mktemp -d)"
trap 'rm -rf "${corpus}"' EXIT

bundle="${corpus}/bundle.pem"
: > "${bundle}"

if [ -x /usr/bin/security ] && [ -r /System/Library/Keychains/SystemRootCertificates.keychain ]; then
  /usr/bin/security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain >> "${bundle}"
fi

for store in /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem /etc/pki/tls/certs/ca-bundle.crt; do
  if [ -r "${store}" ]; then
    cat "${store}" >> "${bundle}"
    break
  fi
done

for extra in "$@"; do
  if [ ! -r "${extra}" ]; then
    echo "cannot read ${extra}" >&2
    exit 1
  fi
  cat "${extra}" >> "${bundle}"
done

certificates="${corpus}/certificates"
mkdir -p "${certificates}"

# one file per certificate, ignoring anything between the blocks: bundles are
# full of comments naming what follows
awk -v dir="${certificates}" '/-----BEGIN CERTIFICATE-----/ { block = 1; n = n + 1 } block { print > sprintf("%s/%04d.pem", dir, n) } /-----END CERTIFICATE-----/ { block = 0 }' "${bundle}"

count="$(find "${certificates}" -name '*.pem' | wc -l | tr -d ' ')"
if [ "${count}" -eq 0 ]; then
  echo "no certificates found: no trust store on this machine, and no bundle given" >&2
  exit 1
fi

echo "checking ${count} certificates"
CERTREADER_CORPUS_DIR="${certificates}" go test ./pkg/print/ -run TestCorpus -count=1
