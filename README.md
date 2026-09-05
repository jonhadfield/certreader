# print TLS certificate info

A fork of the excellent [certinfo](https://github.com/pete911/certinfo), adding:

- **revocation checking** — the OCSP response a server staples to the handshake, and with
  `-revocation` a live check against the certificate's OCSP responders, falling back to its CRLs
- **`-verify`**, which says *why* a chain fails rather than only that it did, and reports what a
  server sends that it should not: a missing intermediate, a root it need not serve, duplicates,
  certificates out of order
- **warnings** on weak signatures, small keys and over-long validity
- **json output** (`-json`) and **exit codes**, so it can be used as a monitoring check rather than
  only read by a person
- **PKCS#12/PFX** and **DER** input alongside PEM, and **CSR** reading
- **starttls** for smtp, imap, pop3, ftp, nntp, ldap and postgres
- clipboard input, colourised output, IPv6 addresses, and bare hostnames
  (`certreader example.com`) defaulting to port 443

[![go](https://github.com/jonhadfield/certreader/actions/workflows/go.yml/badge.svg)](https://github.com/jonhadfield/certreader/actions/workflows/go.yml)
[![release](https://img.shields.io/github/v/release/jonhadfield/certreader)](https://github.com/jonhadfield/certreader/releases/latest)
[![license](https://img.shields.io/github/license/jonhadfield/certreader)](LICENSE)

Output detailed information about TLS certificates from local files, network hosts or clipboard.

![certreader reading two hosts and a certificate request](docs/screenshot.svg)

## usage

```shell script
certreader [flags] [<file>|<host:port> ...]
```

**file** argument can be:
 - **local file path** `certreader <filename>`
 - **TCP network address** `certreader <host:port>` e.g. `certreader google.com:443`
 - **IPv6 address** `certreader <[address]:port>` e.g. `certreader "[2606:2800:21f::1]:443"` (the brackets separate the address from the port, and your shell may need them quoted)
 - **FQDN** `certreader <host>` e.g. `certreader www.example.com` (port 443 is assumed when no local file with that name exists, for an IP address as well as a name)
 - **stdin** `echo "<cert-content>" | certreader`

```
+-------------------------------------------------------------------------------------------------------------------+
| optional flags                                                                                                    |
+---------------+---------------------------------------------------------------------------------------------------+
| -chains       | whether to print verified chains as well                                                          |
| -concurrency  | how many locations to read at once, 0 for no limit (default 100)                                  |
| -clipboard    | read input from clipboard (only if the clipboard is supported)                                    |
| -compare      | compare two locations and report whether they serve the same certificate                          |
| -csr          | force CSR mode (CSRs are auto-detected, so this is optional)                                      |
| -expiry       | print expiry of certificates                                                                      |
| -expiring-within | exit non-zero if any certificate expires within this window, e.g. 30d, 2w, 72h                  |
| -fail-on-warning | exit non-zero if any certificate or chain warning is reported                                   |
| -fingerprint  | print the sha-256 of the certificate and of its public key                                        |
| -follow-redirects| allow a revocation or issuer request to be redirected away from the address the certificate named |
| -extensions   | whether to print extensions                                                                       |
| -insecure     | whether a client verifies the server's certificate chain and host name (only applicable for host) |
| -issuer-like  | print certificates with issuer field containing supplied string                                   |
| -json         | output as json (takes precedence over -expiry and -pem-only)                                      |
| -no-duplicate | do not print duplicate certificates                                                               |
| -no-expired   | do not print expired certificates                                                                 |
| -pem          | whether to print pem as well                                                                      |
| -pem-only     | whether to print only pem (useful for downloading certs from host)                                |
| -pfx-password | password used when parsing PKCS#12/PFX bundles; leave empty for passwordless files                |
| -revocation   | check revocation status via OCSP, falling back to CRL (makes network requests)                    |
| -server-name  | verify the hostname on the returned certificates, useful for testing SNI                          |
| -signature    | whether to print signature                                                                        |
| -starttls     | upgrade a plaintext connection to tls: smtp, imap, pop3, ftp, nntp, ldap, postgres                |
| -sort-expiry  | sort certificates by expiration date                                                              |
| -subject-like | print certificates with subject field containing supplied string                                  |
| -verbose      | trace what is being done, to stderr                                                                |
| -verify       | verify against the system trust store and report why it fails                                     |
| -timeout      | how long to wait for a connection, and proportionally longer for revocation requests (default 5s)  |
| -more         | use a combination of the '-pem -signature -chains' flags                                          |
| -version      | certreader version                                                                                  |
| -help         | help                                                                                              |
+---------------+---------------------------------------------------------------------------------------------------+

When a PKCS#12/PFX input requires a password and no `--pfx-password` value is supplied, `certreader` prompts on the
terminal; set the flag or `CERTREADER_PFX_PASSWORD` for non-interactive usage.
```

## certificate requests

A request is signed by the key it asks to have certified. That self-signature is the only evidence
the requester holds the matching private key, and the only thing binding the subject and the
alternative names to it. Without it a request is a list of claims anyone could have written.

`certreader` checks it and says so, whether or not it holds:

```
Self-Signature: verified against the key in the request
```

```
Self-Signature: self-signature does not verify: crypto/rsa: verification error
```

The rest of the request is still printed either way — it is what the request claims, worth reading
alongside the reason not to believe it. `-fail-on-warning` exits non-zero on one that does not
verify, and `-json` carries `self_signature_valid` along with a warning coded
`invalid-self-signature`.

### where the requests go

`-revocation` and the issuer fetch send requests to addresses written in the certificate, by whoever
issued it. Only those addresses are contacted: a redirect is refused, and says so.

```
Revocation
    OCSP responder (http://ocsp.example.com): redirected to http://10.0.0.1/, which is not where the
    certificate said: allow it with -follow-redirects
```

A redirect can send a request somewhere the certificate has no business naming — a private address,
a service on the machine running this — and the response never has to come back for the request to
have been made. `-follow-redirects` allows it, checks each hop as the first address was checked, and
stops after three.

Refusing them costs nothing in practice: ten public hosts including Google, GitHub, Cloudflare,
Apple, Amazon, Microsoft, Stripe and PayPal all answer without a redirect.

## verbose

`-verbose` traces what the tool is doing, on stderr, so stdout is still the document:

```shell script
certreader -verbose -revocation google.com:443
```

```
level=DEBUG msg=reading locations=1 concurrency=100 timeout=5s
level=DEBUG msg=connecting address=google.com:443 starttls="" timeout=5s server_name=""
level=DEBUG msg=connected address=google.com:443 after=72ms tls="TLS 1.3" certificates=3 stapled_ocsp=false
level=DEBUG msg="checking revocation" subject=*.google.com serial=E0:E3:... stapled=false ocsp_responders=0 crl_distribution_points=1
level=DEBUG msg="reading a CRL" distribution_point=http://c.pki.goog/wr2/oBFYYahzgVI.crl
level=DEBUG msg="downloading a CRL" distribution_point=http://c.pki.goog/wr2/oBFYYahzgVI.crl
level=DEBUG msg="CRL read" distribution_point=http://c.pki.goog/wr2/oBFYYahzgVI.crl revoked_certificates=1387
```

This is the answer to "why did it say that": above, the certificate names no OCSP responder, which is
why a CRL was read instead. A `reading` line with no `downloading` after it is a list already held,
so a scan of many hosts behind one authority shows that it fetched the list once.

## compare

`-compare` takes two locations and says whether they are serving the same certificate:

```shell script
certreader -compare deployed.pem www.example.com:443
```

```
--- [deployed.pem vs www.example.com:443 TLS 1.3] ---
Certificate: same
    SHA-256: 8F:95:CC:30:E8:8F:6B:71:EF:35:1F:71:03:32:85:0C:55:44:E7:59:4A:F4:0B:1A:7E:11:9E:18:EF:D6:10:22
Public Key: same
Chain: different (deployed.pem sends 1, www.example.com:443 sends 3)
Result: the same certificate, sent with a different chain
```

The chain is reported but is not a difference worth failing on: deploying a leaf and serving it with
the intermediates a client needs is normal. Only the certificate decides the exit code, so

```shell script
certreader -compare deployed.pem www.example.com:443 || echo "not serving what was deployed"
```

exits 0 when the certificate matches, 2 when it does not, and 1 if either location could not be read.

When the certificates differ, the key is the interesting half — it separates a reissue from a
rotation:

```
Certificate: different
Public Key: same
Result: different certificates carrying the same key, which is what a reissue looks like
```

`-json` gives the same answer as a document, with `same`, `same_certificate`, `same_key`,
`same_chain` and both fingerprints.

## fingerprints

`-fingerprint` prints two, and they answer different questions:

```shell script
certreader -fingerprint example.com:443
```

```
Fingerprint SHA-256: CB:3C:CB:B7:60:31:E5:E0:13:8F:8D:D3:9A:23:F9:DE:47:FF:C3:5E:43:C1:14:4C:EA:27:D4:6A:5A:B1:CB:5F
Public Key SHA-256: i7WTqTvh0OioIruIfFR4kMPnBqrS2rdiVPl/s2uC/CY=
```

The first names *this certificate*, and is what `openssl x509 -fingerprint -sha256` prints and what a
browser shows. It changes on every reissue, so it answers "is the load balancer serving the same
certificate as this file".

The second names *the key*, base64 encoded, which is the form a pin is written in. It survives a
reissue that keeps the key, so it answers "has the key actually been rotated".

Both are always present in `-json`, as `fingerprint_sha256` and `public_key_sha256`, since something
reading the output would not know to ask for them.

## starttls

Mail, directory and database servers usually begin in plaintext and upgrade to TLS on request, so a
direct handshake cannot reach their certificates. `-starttls` performs the upgrade first:

```shell script
certreader -starttls smtp smtp.gmail.com:587
```

```
--- [smtp.gmail.com:587 TLS 1.3] ---
Subject: CN=smtp.gmail.com
Issuer: CN=WR2,O=Google Trust Services,C=US
```

Supported protocols, and the port assumed when only a hostname is given:

| protocol | port |
|----------|------|
| smtp | 587 |
| imap | 143 |
| pop3 | 110 |
| ftp | 21 |
| nntp | 119 |
| ldap | 389 |
| postgres | 5432 |

So `certreader -starttls imap mail.example.com` connects to port 143, where the same argument without
`-starttls` would use 443. For smtp the submission port is assumed rather than 25, since that is
where a certificate is usually being inspected; give `host:25` explicitly for the relay port.

This applies to network arguments only, and combines with everything else — `-json`, `-revocation`
and `-expiring-within` all work the same over an upgraded connection.

## verify

`-verify` checks the certificate against the system trust store, and against the hostname when the
certificate came from the network, and says why it failed rather than only that it did.

```shell script
certreader -verify example.com:443
```

```
Verification
    Result: verified
    Chains: 1
    Hostname: example.com
```

Each failure is reported with a stable `code` in `-json` output:

| code | meaning |
|------|---------|
| `expired` / `not-yet-valid` | a certificate in the chain is outside its validity period |
| `hostname-mismatch` | the chain is sound, but not for the name it was served under |
| `self-signed` | not issued by any certificate authority |
| `missing-intermediate` | the issuer was never supplied, so the chain cannot be built |
| `untrusted-root` | the chain is complete but does not reach the system trust store |
| `no-end-entity` | there was nothing to verify |

The distinction between `missing-intermediate` and `untrusted-root` is the useful one: both appear as
"unknown authority" otherwise, and the fixes differ — serve the intermediate, or trust the root.

A hostname is only checked for certificates read from the network, since one read from a file is not
being served for any particular name. `-server-name` overrides the name checked.

### chain hygiene

`-verify` also reports how the served chain is put together. These are not failures — every one can
appear on a chain that verifies perfectly well — so they do not change the result:

| code | reported when |
|------|---------------|
| `root-included` | the root is served, which no client can use: it either already trusts it or will not trust it now |
| `duplicate-certificate` | a certificate is sent more than once |
| `chain-out-of-order` | a certificate does not issue the one before it |
| `leaf-not-first` | the first certificate sent is a CA, where the end-entity is expected |
| `missing-intermediate` | the certificate that issued the leaf is not sent |

`missing-intermediate` is the one that breaks clients, and the one hardest to notice: macOS and
Windows keep intermediates they have seen before and fill the gap themselves, so the chain verifies
on the machine it was tested from and fails for anyone whose store happens not to hold it. It is
reported from what the server sent rather than from what this computer can make of it, so the answer
is the same everywhere.

These describe what the server sent, so the display filters do not change them: `-no-duplicate`
removes the duplicate from the output and `duplicate-certificate` is still reported, since the server
sent it either way.

```
Verification
    Result: verified
    Chains: 1
    Hostname: www.digicert.com
    Chain: the root DigiCert Global Root G2 is sent but cannot be used: a client either already
           trusts it or will not trust it now (914 bytes per handshake)
```

Expiry anywhere in the chain, and a missing intermediate, are reported as verification problems
rather than hygiene, since those do stop a client connecting.

These apply to network locations only. A bundle in a file is expected to hold roots and to be in
whatever order suits it, so the same checks there would report the file's purpose as a fault.

`-chains` is the display half of the same thing: it prints the chains that were built, where
`-verify` judges them. Both use one implementation, so they cannot disagree about what a valid chain
is. Chain building deliberately ignores the hostname, so `-chains` still shows what can be built for
a certificate served under the wrong name; `-verify` checks the name separately and reports a
mismatch as itself.

## warnings

Weaknesses are reported alongside the certificate, without needing a flag:

```
Warnings
    signed with SHA1-RSA, which is no longer considered sound
    1024 bit rsa key, below the 2048 bit minimum
    valid for 800 days, beyond the 398 day maximum for server certificates
    no subject alternative name, which browsers require and will not read from the common name
```

| code | reported when |
|------|---------------|
| `weak-signature-algorithm` | signed with MD2, MD5 or SHA-1 |
| `small-key` | RSA below 2048 bits, ECDSA below 256, or DSA at all |
| `long-validity` | a server certificate valid for more than 398 days |
| `missing-subject-alt-name` | a server certificate with no DNS name or IP address |

Each warning carries a stable `code` in `-json` output, so a check can match on that rather than on
the wording.

They are deliberately quiet where a property is only weak out of context. A root's own signature is
not reported, because a root is trusted by being in a trust store rather than by its signature, so
flagging every SHA-1 era root would be noise. The validity and name rules apply only to certificates
offered for server authentication, and only from September 2020, when the 398 day limit took effect —
certificates issued before it were legitimately longer lived.

Warnings do not affect the exit code by default. Whether a weak certificate should fail a check is a
policy decision, and changing what an existing `-expiring-within` check returns would be the wrong
way to make it.

`-fail-on-warning` opts in: any warning then counts as a failed check and exits `2`, alongside
revoked and expiring certificates.

```shell script
certreader -verify -fail-on-warning example.com:443 || echo "needs attention"
```

Chain warnings are only worked out by `-verify`, so `-fail-on-warning` without it considers the
certificates alone.

## exit codes

| code | meaning |
|------|---------|
| 0 | everything read, and any checks asked for passed |
| 1 | a location could not be read, so its status is unknown rather than good |
| 2 | a check failed: a certificate is revoked, or expires within `-expiring-within` |

Checks are opt-in. Without `-revocation` nothing is known about revocation, and without
`-expiring-within` an expired certificate is reported but not treated as a failure — inspecting an
expired certificate is a normal thing to want to do.

```shell script
certreader -revocation -expiring-within 14d example.com:443 || echo "needs attention"
```

`-expiring-within` accepts go duration syntax plus day and week suffixes: `30d`, `2w`, `72h`, `90m`.
A window of `0` means "already expired", and an expired certificate falls inside any window.

Where both apply, a failed check (2) outranks a load error (1): a certificate known to be revoked is
more actionable than one that could not be read, and load failures are reported on stderr anyway.
Only what survives the filtering flags is checked, so `-no-expired` excludes certificates from the
checks as well as from the output.

## json output

`-json` emits a single JSON document on stdout instead of the formatted text, for piping into `jq` or
a monitoring check. Logging goes to stderr, so the document stays clean even with `-verbose`.

```shell script
certreader -json www.digicert.com | jq -r '.locations[].certificates[0] | "\(.subject) expires \(.not_after)"'
```

```shell script
certreader -json -revocation www.digicert.com | jq -r '.locations[].revocation.status'
```

Every location becomes an entry under `locations`, carrying `certificates` or `csrs`, and the
revocation result when one was requested. A location that failed to load reports an `error` instead,
and a certificate that failed to parse carries only its `position` and `error`, since nothing else
could be read from it. Timestamps are RFC 3339.

The `extensions`, `signature` and `pem` fields are included only when the corresponding flags are
set, matching what the text output would show, so `-json -more -extensions` gives everything.

Field names are part of the interface and will be added to rather than renamed.

## revocation

By default, when reading from a network host, `certreader` prints the OCSP response the server stapled to the TLS
handshake, if it sent one. This is the revocation status the server volunteered — no request is made to the CA, so it
costs no extra connection.

```
OCSP Staple
    Status: good
    Serial Number: 08:06:62:87:89:15:B4:2A:0E:4D:C6:1A:4D:AE:DF:EA
    Produced At: Aug 24 11:13:27 2026 UTC
    This Update: Aug 24 10:57:00 2026 UTC
    Next Update: Aug 31 09:57:00 2026 UTC
    Signature: verified against issuer
```

`-revocation` goes further and actively determines the status, using the first source that answers:

1. the stapled response, when there is one and it has not expired — no request needed
2. the OCSP responders named in the certificate's authority information access extension
3. the certificate's CRL distribution points

```shell script
certreader -revocation revoked.badssl.com
```

```
Revocation
    Status: revoked
    Source: CRL (http://ye1.c.lencr.org/34.crl)
    Serial Number: 05:C3:91:E0:61:DE:65:88:F6:70:B6:13:F0:61:AE:F4:B3:A1
    Revoked At: Jul 14 21:01:28 2026 UTC
    Reason: key compromise
    This Update: Aug 24 16:42:41 2026 UTC
    Next Update: Sep  2 16:42:40 2026 UTC
    Signature: verified against issuer
    Not Answered
        OCSP responder: certificate names no OCSP responder
```

`Source` names where the verdict came from, and `Not Answered` lists the sources that were consulted first without
producing one. The CRL fallback matters in practice: several CAs, Let's Encrypt and Google among them, no longer publish
OCSP responder URLs at all.

Responses and lists are verified against the issuing CA. When the issuer was not presented alongside the certificate —
reading a single leaf from a file, say — it is downloaded from the certificate's authority information access
extension, and the output says where from:

```
    Signature: verified against issuer
    Issuer: fetched from http://cacerts.digicert.com/DigiCertEVRSACAG2.crt
```

A downloaded certificate is only used once it has been shown to have signed the one being checked, since the fetch is
plain http. If no issuer can be obtained, OCSP is skipped, as no request can be built without one, and any CRL verdict
is reported as `not verified`. A verdict past its `Next Update` is marked `[stale]`.

### interpreting the result

A status of `unknown` means no source could be reached or trusted — it is not the same as the certificate being valid,
and neither is the absence of a stapled response. Only `revoked` is a firm answer; treat `good` as "no source said
otherwise at the time it was checked".

A CRL and an issuer certificate are each fetched once per URL for the whole run, however many hosts
need them, and simultaneous checks share the one fetch rather than each starting their own. A CRL
from a public CA can be tens of megabytes, so scanning many hosts behind one authority would
otherwise download the same file once per host.

Requests honour `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`, as the connection to the host itself does
(see [proxies](#proxies)). Each request is bounded by a 10 second timeout, the whole
check by 30 seconds, and response bodies by 32MB. Revocation is checked only for the default output, not for `-expiry`
or `-pem-only`.

## timeouts

`-timeout` (default `5s`) bounds a connection, and for `-starttls` the negotiation and handshake
together. It takes go duration syntax, such as `10s`, `500ms` or `1m30s`.

A revocation check makes several requests one after another and a CRL can be large, so those are
given proportionally longer: each request twice the timeout, and the whole check six times it. At the
default that comes to 10 seconds a request and 30 seconds overall, which is what these were before
they became configurable.

```shell script
certreader -timeout 30s -revocation slow.example.com:443
```

## proxies

A connection to a host goes through the proxy named by `HTTPS_PROXY` (or `https_proxy`), opened with
an HTTP `CONNECT` tunnel. The handshake then runs end to end with the target through that tunnel, so
the certificates reported are the target's own and SNI still names the target rather than the proxy.

```shell script
HTTPS_PROXY=http://proxy.example.com:3128 certreader example.com:443
```

`NO_PROXY` (or `no_proxy`) excludes addresses, following the same rules as go's own client: `*`
excludes everything, and an entry may name a host, a domain suffix, an IP address or a CIDR block,
optionally with a port that must match as well. `localhost` and loopback addresses are never proxied,
whether or not they are listed.

The proxy address may be written as a URL or as a bare `host:port`, which means `http`. Credentials
in the URL are offered as `Proxy-Authorization: Basic`, and are not printed by `-verbose`, which
otherwise names the proxy each connection used.

```shell script
HTTPS_PROXY=http://someone:s3cret@proxy.example.com:3128 certreader -verbose example.com:443
NO_PROXY=.internal.example.com,10.0.0.0/8 certreader host.internal.example.com:443
```

An `https://` proxy is spoken to over TLS, so the `CONNECT` exchange is itself encrypted; the tunnel
it opens still carries a separate handshake with the target. `-insecure` then applies to that hop as
well, since it is the same instruction not to verify, one hop earlier. A `socks5://` or other scheme
is rejected rather than ignored.

`-starttls` is tunnelled the same way, so the plaintext negotiation is with the target and not with
the proxy.

A proxy that terminates TLS rather than tunnelling it will present its own certificate, and that is
what will be reported — which is the honest answer, but worth knowing before reading it as the
target's.

Revocation and issuer requests are ordinary HTTP, and honour `HTTP_PROXY` as well; see
[revocation](#revocation).

## concurrency

Arguments are read at the same time rather than one after another, so checking many hosts is quick.
`-concurrency` bounds how many at once, defaulting to 100.

The default sits well above what checking a handful of hosts will reach, so ordinary use is
unaffected, while a list of hundreds is held to a number of sockets a machine will lend it. Lower it
if you hit file descriptor limits or upstream rate limits; `-concurrency 0` removes the bound
entirely.

The same bound applies to revocation checks. Each check can make several requests of its own, so it
counts conversations in flight rather than sockets.

If you need to run against multiple hosts, it is faster to execute command with multiple arguments e.g.
`certreader -insecure -expiry google.com:443 amazon.com:443 ...` rather than executing command multiple times. Args are
executed concurrently and much faster.

Flags can be set as env. variable as well (`CERTREADER_<FLAG>=true` e.g. `CERTREADER_INSECURE=true`) and can be then
overridden with a flag.

## download

 - [binary](https://github.com/jonhadfield/certreader/releases)

Each archive carries a signed statement of which workflow built it, from which commit:

```shell script
gh attestation verify certreader_0.23.0_darwin_arm64.tar.gz --repo jonhadfield/certreader
```

The checksums published beside the archives say only that a download was not corrupted, since whoever
could change one could change the other. This is checked against GitHub rather than against the
release, and needs no key from anyone. It says the artefact came from this repository's release
workflow; it does not say the source is good.

## build/install

### brew

#### a fresh install

```shell script
brew tap jonhadfield/certreader
brew trust jonhadfield/certreader
brew install certreader
```

Homebrew 6 refuses to load anything from a third-party tap until the tap is trusted, so `brew trust`
comes before the install rather than after it fails.

#### replacing the cask

certreader was a cask until v0.24.0 and is a formula from v0.25.0. If you installed the cask, replace
it once:

```shell script
brew uninstall --cask certreader
brew install certreader
```

### linux

```shell script
curl -sL https://raw.githubusercontent.com/jonhadfield/certreader/main/install | sh
```

This works out the latest release, downloads the archive for the machine it is run on, checks it
against the sums published beside it, and installs to `/usr/local/bin`. The directory is created if
it is not there, and `sudo` is used only if it cannot be written to otherwise. A download that does
not match its checksum is refused, and nothing is installed. It reads three optional variables:

| variable | |
| --- | --- |
| `CERTREADER_VERSION` | a tag to install, e.g. `v0.25.1`. Default: the latest release |
| `CERTREADER_INSTALL_DIR` | where to put the binary. Default: `/usr/local/bin` |
| `GITHUB_URL` | for a mirror or an enterprise host |

```shell script
curl -sL https://raw.githubusercontent.com/jonhadfield/certreader/main/install | CERTREADER_INSTALL_DIR=~/.local/bin sh
```

The variable goes on the `sh` at the end of the pipe, not on the `curl` at the front, which would set
it for the download instead of for the script.

amd64 and arm64 are built; anything else is refused with a message rather than a failed download. The
script runs on macOS too, though `brew` is the supported route there.

### go

[go](https://golang.org/dl/) has to be installed.
 - build `make build`
 - install `make install`

## corpus check

`make test` compares known certificates against known output, which covers the cases somebody
thought to write down. `make corpus` asks a different question — one that has to hold for *any*
certificate — and puts it to every certificate in the machine's trust store:

- the output is text a terminal can print, with no raw bytes in it
- `-json` produces a document that parses

```shell script
make corpus
scripts/corpus-check.sh some-bundle.pem      # and anything else you have
```

Certificates are copied to a temporary directory and removed on exit. Nothing is sent anywhere, and
nothing is added to the repository.

This is how a user notice held as a BMPString was found printing as raw UTF-16, NUL bytes and all:
two certificates out of a few hundred, neither of which anyone would have thought to write a test
for. That certificate is a fixture now, so `make test` covers it, and the same sweep runs over the
fixtures on every test run.

## release

Releases are built and published with [GoReleaser](https://goreleaser.com) from a tagged commit.
Pushing the tag is all that is needed — the `release` workflow builds every platform and uploads the
artifacts to a single GitHub release, then updates the homebrew formula.

```shell script
git tag -a -m "add super cool feature" v1.0.0
git push --follow-tags
```

### required secret

Platform builds run in parallel, so a release takes about as long as its slowest target rather than
the sum of all five. A prerelease tag (one containing a hyphen, such as `v1.0.0-rc1`) is published as
a prerelease and does not update the homebrew formula.

Release notes come from the annotated tag message, so write the tag with the notes you want.

The workflow needs a `RELEASE_TOKEN` repository secret: a personal access token with `repo` scope on
both `jonhadfield/certreader` and `jonhadfield/homebrew-certreader`. The token built into Actions
cannot write to another repository, and the darwin build pushes the formula update to the tap.

Without it the workflow stops at its preflight job and publishes nothing.

Run the workflow manually from the Actions tab to check the secret and the GoReleaser configs
without cutting a tag; a manual run stops after preflight.

### why a formula and not a cask

Homebrew marks what a **cask** installs with `com.apple.quarantine`, and gatekeeper kills a
quarantined binary that carries no stapled notarization ticket. The command exits 137 and prints
nothing, which reads like a broken build rather than a refused one:

```shell script
$ certreader -version
$ echo $?
137
```

A bare executable has nowhere to keep a ticket — `stapler` needs an app bundle, a disk image or an
installer package — so signing and notarizing the binary does not settle it. On macOS 26.5 a binary
signed with a Developer ID certificate and accepted by the notary service was still refused under
quarantine, on every attempt within ten minutes of the ticket being issued.

A **formula** is not quarantined, which is how every other Go command line tool in Homebrew arrives
able to run. GoReleaser calls `brews` deprecated in favour of `homebrew_casks`; the cask is what
certreader shipped as up to v0.24.0, and it did not run when installed, so the formula stays until
there is something to staple a ticket to.

### releasing by hand

The same builds can be run locally, which is useful when debugging a release failure:

```shell script
GITHUB_TOKEN=$(gh auth token) make release
```

This needs Docker, a local `goreleaser`, and a clean working tree. Individual platforms can be built
on their own, e.g. `make release-mac` or `make release-linux-arm64`. Both routes use the same make
targets and the configs in `.goreleaser/`, building darwin on the host and linux/windows inside
`goreleaser-cross` containers.

## examples

### remove expired and malformed certs

- `-pem-only` returns only the pem blocks that parse and are certificates
- `-no-expired` removes expired certificates

`certreader -pem-only -no-expired <chain-file>.pem > <new-chain-file>.pem`

### certificate transparency

`-extensions` decodes the embedded SCTs, which prove the certificate was submitted to public
certificate transparency logs:

```
CT Precertificate SCTs (1.3.6.1.4.1.11129.2.4.2)
    Signed Certificate Timestamp:
        Version   : v1 (0x0)
        Log ID    : C2:31:7E:57:45:19:A3:45:EE:7F:38:DE:B2:90:41:EB:C7:C2:21:5A:22:BF:7F:D5:B5:AD:76:9A:D9:0E:52:CD
        Timestamp : Aug 10 06:13:28.444 2026 UTC
        Extensions: none
        Signature : ECDSA-SHA256
                    30:44:02:20:30:D0:33:28:8F:49:A6:B2:00:9E:5D:77:
                    ...
```

The log is identified by the SHA-256 hash of its public key; there is no name, since mapping ids to
names needs a list that goes stale.

### info/verbose

`certreader www.digicert.com:443`
```
--- [www.digicert.com:443 TLS 1.3] ---
Version: 3
Serial Number: 08:06:62:87:89:15:B4:2A:0E:4D:C6:1A:4D:AE:DF:EA
Signature Algorithm: SHA256-RSA
Type: end-entity
Issuer: CN=DigiCert EV RSA CA G2,O=DigiCert Inc,C=US
Validity
    Not Before: Aug 10 00:00:00 2026 UTC
    Not After: Sep 25 23:59:59 2026 UTC
Subject: CN=www.digicert.com,O=DigiCert\, Inc.,L=Lehi,ST=Utah,C=US,SERIALNUMBER=5299537-0142,2.5.4.15=#131450726976617465204f7267616e697a6174696f6e,1.3.6.1.4.1.311.60.2.1.2=#130455746168,1.3.6.1.4.1.311.60.2.1.3=#13025553
DNS Names: www.digicert.com, digicert.com
IP Addresses: 
Authority Key Id: 6A:4E:50:BF:98:68:9D:5B:7B:20:75:D4:59:01:79:48:66:92:32:06
Subject Key
    Id: C8:55:B6:D1:45:24:87:58:39:F8:14:0A:64:CE:11:B7:C1:FC:72:69
    Algorithm: RSA
Key Usage: Digital Signature, Key Encipherment
Ext Key Usage: Server Auth
CA: false

Version: 3
Serial Number: 01:67:8F:1F:EF:88:22:55:D8:B0:A7:0E:6B:7B:B2:20
Signature Algorithm: SHA256-RSA
Type: intermediate
Issuer: CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US
Validity
    Not Before: Jul  2 12:42:50 2020 UTC
    Not After: Jul  2 12:42:50 2030 UTC
Subject: CN=DigiCert EV RSA CA G2,O=DigiCert Inc,C=US
DNS Names: 
IP Addresses: 
Authority Key Id: 4E:22:54:20:18:95:E6:E3:6E:E6:0F:FA:FA:B9:12:ED:06:17:8F:39
Subject Key
    Id: 6A:4E:50:BF:98:68:9D:5B:7B:20:75:D4:59:01:79:48:66:92:32:06
    Algorithm: RSA
Key Usage: Digital Signature, Cert Sign, CRL Sign
Ext Key Usage: Server Auth, Client Auth
CA: true

Version: 3
Serial Number: 03:3A:F1:E6:A7:11:A9:A0:BB:28:64:B1:1D:09:FA:E5
Signature Algorithm: SHA256-RSA
Type: root
Issuer: CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US
Validity
    Not Before: Aug  1 12:00:00 2013 UTC
    Not After: Jan 15 12:00:00 2038 UTC
Subject: CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US
DNS Names: 
IP Addresses: 
Authority Key Id: 
Subject Key
    Id: 4E:22:54:20:18:95:E6:E3:6E:E6:0F:FA:FA:B9:12:ED:06:17:8F:39
    Algorithm: RSA
Key Usage: Digital Signature, Cert Sign, CRL Sign
Ext Key Usage: 
CA: true

OCSP Staple
    Status: good
    Serial Number: 08:06:62:87:89:15:B4:2A:0E:4D:C6:1A:4D:AE:DF:EA
    Produced At: Aug 30 11:13:27 2026 UTC
    This Update: Aug 30 10:57:00 2026 UTC
    Next Update: Sep  6 09:57:00 2026 UTC
    Signature: verified against issuer
```

### expiry

`certreader -expiry www.digicert.com`

Each line names the certificate it refers to, since every line in a chain shares the same prefix:

```
www.digicert.com TLS 1.3: Sep 25 23:59:59 2026 UTC  www.digicert.com
www.digicert.com TLS 1.3: Jul  2 12:42:50 2030 UTC  DigiCert EV RSA CA G2
www.digicert.com TLS 1.3: Jan 15 12:00:00 2038 UTC  DigiCert Global Root G2
```

### show certificate with specific subject
This example shows AWS RDS certificates for specific region (we can also see AWS started using 100 years expiration)
- show only eu-west-2 certs `curl https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem | certreader -subject-like eu-west-2`
- download only eu-west-2 certs `curl https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem | certreader -subject-like eu-west-2 -pem-only > rds-eu-west-2.pem`

  These entries are self-signed roots, so `-issuer-like` returns the same three certificates. The two
  differ on a chain, where the subject is the certificate and the issuer is what signed it.

### verify SNI certificates
Specific host can be set by `server-name` flag. This is useful if we need to verify that load balancer is correctly
using certificates for different hosts: `certreader -server-name <host> <load-balancer|proxy>` e.g.
`certreader -server-name tabletmag.com  cname.vercel-dns.com:443` (tabletmag certificate behind vercel).

### local root certs

- linux `ls -d /etc/ssl/certs/* | grep '.pem' | xargs certreader -expiry`
- mac `cat /etc/ssl/cert.pem | certreader -expiry`
