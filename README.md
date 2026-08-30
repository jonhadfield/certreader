# print TLS certificate info

A fork of the excellent [certinfo](https://github.com/pete911/certinfo), adding:

- **revocation checking** — the OCSP response a server staples to the handshake, and with
  `-revocation` a live check against the certificate's OCSP responders, falling back to its CRLs
- **json output** (`-json`) and **exit codes**, so it can be used as a monitoring check rather than
  only read by a person
- **PKCS#12/PFX** and **DER** input alongside PEM, and **CSR** reading
- clipboard input, colourised output, and bare hostnames (`certreader example.com`) defaulting to
  port 443

[![go](https://github.com/jonhadfield/certreader/actions/workflows/go.yml/badge.svg)](https://github.com/jonhadfield/certreader/actions/workflows/go.yml)
[![release](https://img.shields.io/github/v/release/jonhadfield/certreader)](https://github.com/jonhadfield/certreader/releases/latest)
[![license](https://img.shields.io/github/license/jonhadfield/certreader)](LICENSE)

Output detailed information about TLS certificates from local files, network hosts or clipboard.

## usage

```shell script
certreader [flags] [<file>|<host:port> ...]
```

**file** argument can be:
 - **local file path** `certreader <filename>`
 - **TCP network address** `certreader <host:port>` e.g. `certreader google.com:443`
 - **FQDN** `certreader <host>` e.g. `certreader www.example.com` (port 443 is assumed when no local file with that name exists)
 - **stdin** `echo "<cert-content>" | certreader`

```
+-------------------------------------------------------------------------------------------------------------------+
| optional flags                                                                                                    |
+---------------+---------------------------------------------------------------------------------------------------+
| -chains       | whether to print verified chains as well                                                          |
| -clipboard    | read input from clipboard (only if the clipboard is supported)                                    |
| -expiry       | print expiry of certificates                                                                      |
| -expiring-within | exit non-zero if any certificate expires within this window, e.g. 30d, 2w, 72h                  |
| -extensions   | whether to print extensions                                                                       |
| -insecure     | whether a client verifies the server's certificate chain and host name (only applicable for host) |
| -issuer-like  | print certificates with subject field containing supplied string                                  |
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
| -subject-like | print certificates with issuer field containing supplied string                                   |
| -verify       | verify against the system trust store and report why it fails                                     |
| -timeout      | how long to wait for a connection, and proportionally longer for revocation requests (default 5s)  |
| -more         | use a combination of the '-pem -signature -chains' flags                                          |
| -version      | certreader version                                                                                  |
| -help         | help                                                                                              |
+---------------+---------------------------------------------------------------------------------------------------+

When a PKCS#12/PFX input requires a password and no `--pfx-password` value is supplied, `certreader` prompts on the
terminal; set the flag or `CERTREADER_PFX_PASSWORD` for non-interactive usage.
```

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

Verification is independent of `-chains`, which shows the chains that were built rather than
explaining a failure, and does not check the hostname at all.

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

Warnings do not affect the exit code. Whether a weak certificate should fail a check is a policy
decision, and quietly changing what an existing `-expiring-within` check returns would be the wrong
way to make it.

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

Requests honour `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`. Each request is bounded by a 10 second timeout, the whole
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

If you need to run against multiple hosts, it is faster to execute command with multiple arguments e.g.
`certreader -insecure -expiry google.com:443 amazon.com:443 ...` rather than executing command multiple times. Args are
executed concurrently and much faster.

Flags can be set as env. variable as well (`CERTREADER_<FLAG>=true` e.g. `CERTREADER_INSECURE=true`) and can be then
overridden with a flag.

## download

 - [binary](https://github.com/jonhadfield/certreader/releases)

## build/install

### brew

- brew tap jonhadfield/certreader
- brew install --cask certreader

### go

[go](https://golang.org/dl/) has to be installed.
 - build `make build`
 - install `make install`

## release

Releases are built and published with [GoReleaser](https://goreleaser.com) from a tagged commit.
Pushing the tag is all that is needed — the `release` workflow builds every platform and uploads the
artifacts to a single GitHub release, then updates the homebrew cask.

```shell script
git tag -a -m "add super cool feature" v1.0.0
git push --follow-tags
```

### required secret

Platform builds run in parallel, so a release takes about as long as its slowest target rather than
the sum of all five. A prerelease tag (one containing a hyphen, such as `v1.0.0-rc1`) is published as
a prerelease and does not update the homebrew cask.

Release notes come from the annotated tag message, so write the tag with the notes you want.

The workflow needs a `RELEASE_TOKEN` repository secret: a personal access token with `repo` scope on
both `jonhadfield/certreader` and `jonhadfield/homebrew-certreader`. The token built into Actions
cannot write to another repository, and the darwin build pushes the cask update to the tap. Without
the secret the workflow stops at its preflight job and publishes nothing.

Run the workflow manually from the Actions tab to check the secret and the GoReleaser configs
without cutting a tag; a manual run stops after preflight.

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

- `--pem-only` flag returns only pem blocks that can be parsed and are type of certificate
- `--no-expired` flag removes expired certificates

`certreader --pem-only --no-expired <chain-file>.pem > <new-chain-file>.pem`

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

`certreader vault.com:443`
```
--- [vault.com:443 TLS 1.2] ---
Version: 3
Serial Number: 16280914906313700456
Signature Algorithm: SHA256-RSA
Type: end-entity
Issuer: CN=Go Daddy Secure Certificate Authority - G2,OU=http://certs.godaddy.com/repository/,O=GoDaddy.com\, Inc.,L=Scottsdale,ST=Arizona,C=US
Validity
    Not Before: Mar 24 10:44:12 2022 UTC
    Not After : Mar 19 13:04:10 2023 UTC
Subject: CN=*.vault.com
DNS Names: *.vault.com, vault.com
IP Addresses:
Authority Key Id: 40c2bd278ecc348330a233d7fb6cb3f0b42c80ce
Subject Key
    Id       : 6b8c8d1da18cbb8cd64437ed0a9c8a0fef673821
    Algorithm: RSA
Key Usage: Digital Signature, Key Encipherment
Ext Key Usage: Server Auth, Client Auth
CA: false

Version: 3
Serial Number: 7
Signature Algorithm: SHA256-RSA
Type: intermediate
Issuer: CN=Go Daddy Root Certificate Authority - G2,O=GoDaddy.com\, Inc.,L=Scottsdale,ST=Arizona,C=US
Validity
    Not Before: May  3 07:00:00 2011 UTC
    Not After : May  3 07:00:00 2031 UTC
Subject: CN=Go Daddy Secure Certificate Authority - G2,OU=http://certs.godaddy.com/repository/,O=GoDaddy.com\, Inc.,L=Scottsdale,ST=Arizona,C=US
DNS Names:
IP Addresses:
Authority Key Id: 3a9a8507106728b6eff6bd05416e20c194da0fde
Subject Key
    Id       : 40c2bd278ecc348330a233d7fb6cb3f0b42c80ce
    Algorithm: RSA
Key Usage: Cert Sign, CRL Sign
Ext Key Usage:
CA: true

Version: 3
Serial Number: 1828629
Signature Algorithm: SHA256-RSA
Type: intermediate
Issuer: OU=Go Daddy Class 2 Certification Authority,O=The Go Daddy Group\, Inc.,C=US
Validity
    Not Before: Jan  1 07:00:00 2014 UTC
    Not After : May 30 07:00:00 2031 UTC
Subject: CN=Go Daddy Root Certificate Authority - G2,O=GoDaddy.com\, Inc.,L=Scottsdale,ST=Arizona,C=US
DNS Names:
IP Addresses:
Authority Key Id: d2c4b0d291d44c1171b361cb3da1fedda86ad4e3
Subject Key
    Id       : 3a9a8507106728b6eff6bd05416e20c194da0fde
    Algorithm: RSA
Key Usage: Cert Sign, CRL Sign
Ext Key Usage:
CA: true

--- 1 verified chains ---
```

### info/expiry

`certreader -expiry google.com:443`
```
--- [google.com:443 TLS 1.3] ---
Subject: CN=*.google.com
Expiry: 2 months 4 days 14 hours 41 minutes

Subject: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
Expiry: 4 years 6 months 19 days 5 hours 29 minutes

Subject: CN=GTS Root R1,O=Google Trust Services LLC,C=US
Expiry: 4 years 10 months 17 days 4 hours 29 minutes
```

### show certificate with specific subject
This example shows AWS RDS certificates for specific region (we can also see AWS started using 100 years expiration)
- show only eu-west-2 certs `curl https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem | certreader -issuer-like eu-west-2`
- download only eu-west-2 certs `curl https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem | certreader -issuer-like eu-west-2 -pem-only > rds-eu-west-2.pem`

### verify SNI certificates
Specific host can be set by `server-name` flag. This is useful if we need to verify that load balancer is correctly
using certificates for different hosts: `certreader -server-name <host> <load-balancer|proxy>` e.g.
`certreader -server-name tabletmag.com  cname.vercel-dns.com:443` (tabletmag certificate behind vercel).

### local root certs

- linux `ls -d /etc/ssl/certs/* | grep '.pem' | xargs certreader -expiry`
- mac `cat /etc/ssl/cert.pem | certreader -expiry`
