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

Responses and lists are verified against the issuing CA. When the issuer is not available the OCSP step is skipped, as
no request can be built without it, and any CRL verdict is reported as `not verified`. A verdict past its `Next Update`
is marked `[stale]`.

### interpreting the result

A status of `unknown` means no source could be reached or trusted — it is not the same as the certificate being valid,
and neither is the absence of a stapled response. Only `revoked` is a firm answer; treat `good` as "no source said
otherwise at the time it was checked".

Requests honour `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`. Each request is bounded by a 10 second timeout, the whole
check by 30 seconds, and response bodies by 32MB. Revocation is checked only for the default output, not for `-expiry`
or `-pem-only`.

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
