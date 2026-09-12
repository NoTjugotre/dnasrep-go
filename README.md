# dnasrep (Go)

A single, dependency-free Go binary that replaces the entire **DNASrep** stack
(dnsmasq + a weak-cipher Apache/OpenSSL build + PHP scripts). It combines:

1. **DNS redirector** – answers `gate1.{jp,eu,us}.dnas.playstation.org` (i.e.
   anything under `dnas.playstation.org`) with the server's own IP and forwards
   all other queries to an upstream resolver. Extra names (e.g.
   `www01.kddi-mmbb.jp`) can be added via a [`dns.config`](#dns-redirect-rules)
   file. Replaces `etc/dnsmasq.d/dnas`.
2. **TLS 1.0 server** – a small, purpose-built TLS 1.0 implementation
   ([`tls10.go`](tls10.go)) that presents the original per-region certificates
   from `etc/dnas/` and speaks the exact dialect a PS2 expects: an
   SSLv2-compatible CLIENT-HELLO, RSA key exchange, and
   `TLS_RSA_WITH_3DES_EDE_CBC_SHA`. Go's own `crypto/tls` cannot be used here
   (see [Why a hand-rolled TLS 1.0 server](#why-a-hand-rolled-tls-10-server)).
   Replaces the three Apache virtual hosts and their patched OpenSSL.
3. **Packet replay** – ports `connect.php` (3DES-EDE-CBC encryption with keys
   derived from the request packet) and `others.php` (raw replay) one-to-one to
   Go. Replies are sent as **HTTP/1.0** with `Content-Type: image/gif`,
   identical to Apache's `force-response-1.0` that keeps the PS2 from throwing
   "error 106".

Only the standard library is used (`crypto/des`, `crypto/rsa`, `crypto/md5`,
`crypto/sha1`, `net`, …) – no `go get` required.

## Building

Go 1.19 or newer (the code sticks to that API level on purpose, so it builds
on older distribution toolchains):

```sh
cd dnasrep-go
go build -o dnasrep .
```

## Running

Default paths are relative to the working directory:

```sh
sudo ./dnasrep \
  -docroot ./gate \
  -certdir ./certs \
  -redirect-ip 192.168.1.50        # IP the PS2 should resolve the DNAS names to
```

`sudo` is only needed because DNS on `:53` and HTTPS on `:443` are privileged ports.

### Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `-docroot` | `./gate` | document root containing `us-gw/`, `eu-gw/`, `gai-gw/`, `bbnavi/` |
| `-certdir` | `./certs` | directory holding `cert-{jp,eu,us}[-key].pem` and `ca-cert.pem` |
| `-https` | `:443` | TLS listen address(es), comma-separated or repeated |
| `-dns` | `:53` | UDP address of the DNS redirector (`""` disables DNS) |
| `-upstream` | `1.1.1.1:53` | upstream resolver for non-DNAS queries |
| `-redirect-ip` | auto | IP the DNAS names resolve to (default: detected outbound IP) |
| `-dns-suffix` | `dnas.playstation.org` | domain suffix(es) to redirect |
| `-dns-config` | `dns.config` | extra redirect rules file (see below) |
| `-default-region` | `jp` | certificate region used when no DNS lookup revealed the client's region (see below) |
| `-force-success` | `off` | use the gateway's `success.raw`: `fallback` or `always` (experimental, see below) |

On the PS2, set this machine as the **primary DNS**; the redirector handles the rest.

## DNS redirect rules

Beyond the built-in `-dns-suffix`, additional hostnames can be redirected via a
config file (`dns.config` by default; override with `-dns-config`). A copy-ready
template is in [`dns.config.example`](dns.config.example). One rule per line:

```
# <name> [ip]   — ip defaults to -redirect-ip (this server)
dnas.playstation.org
www01.kddi-mmbb.jp        192.168.2.30
```

`<name>` matches the host itself and any subdomain. The most specific (longest)
match wins, and rules in the file override the `-dns-suffix` defaults for the
same name. Names with no matching rule are forwarded to `-upstream`. A missing
`dns.config` is fine (the built-in DNAS defaults still apply); a file explicitly
passed with `-dns-config` that is missing or malformed is a startup error.

## Force-success workaround (experimental)

Every gateway directory holds an `error.raw` — the "auth failed" reply that is
sent whenever a request has no matching capture in `packets/`. Titles that were
never captured for the DNASforever project therefore always get an error, even
though a generic "success" answer might be all they need. `success.raw` is the
counterpart: it lives next to `error.raw`, one per gateway
(`gate/us-gw/success.raw`, `gate/eu-gw/success.raw`, `gate/gai-gw/success.raw`).

`-force-success` decides when it is used:

| Mode | Behaviour |
| --- | --- |
| `off` (default) | captured packets are replayed, uncaptured titles get `error.raw` — original DNASrep behaviour |
| `fallback` | captured packets are replayed **unchanged**; only the `error.raw` case is replaced by `success.raw` |
| `always` | *every* request is answered with `success.raw`, captured packets are ignored entirely |

```sh
./dnasrep -force-success=fallback     # the workaround proper
./dnasrep -force-success=always       # blunt test mode
```

Both modes cover both replay endpoints (`v2.5_i-connect` and `v2.5_others`), and
`success.raw` is sent verbatim — no 3DES envelope is applied, exactly as with
`error.raw`. If a gateway has no `success.raw`, the request falls back to
`error.raw` and a warning is logged. Overridden requests are logged as
`https: force-success: no capture "<id>_<qrytype>" - answering with success.raw`
(`fallback`) or `https: force-success: answering <path> with success.raw`
(`always`).

`fallback` is the mode meant for actual use: it only affects titles that would
have failed anyway. `always` exists to check whether *already emulated* titles
still work when they get the generic reply instead of their real capture — that
answers whether `fallback` can safely become the default, but it is not a mode
to run a working setup on. Note that `-force-success` needs an explicit value;
bare `-force-success` is a usage error rather than a guessed mode.

Whether a console accepts the generic reply is title-dependent — **please report
results.**

## Logging

Every client that reaches the server is logged:

- **Connection level** – each accepted TCP connection is logged with its remote
  IP (`https: connection from <ip>`). This captures clients even when the TLS
  handshake later fails, which a request-level log would miss.
- **Handshake level** – each ClientHello is summarised
  (`tls: <ip> ClientHello: SSLv2-compat, version 3.1, 25 cipher specs, 16-byte challenge`),
  and a handshake that dies is logged with what the client sent instead of the
  expected message, alerts decoded, plus the offered cipher list (a fingerprint
  of the title's TLS stack) and the certificate we presented:
  `tls: <ip> handshake/serve: tls: expected ClientKeyExchange, got fatal alert 46 (certificate_unknown) (ClientHello: …; specs 000066…; presented CN=gate1.jp.dnas.playstation.org, SHA1-RSA, valid 2000-01-01..2037-12-31)`.
  The alert description is the console telling you *why* it gave up
  (`unknown_ca`/`bad_certificate` → chain or CA problem, `certificate_expired`
  or `certificate_unknown` → see [Certificates](#certificates), and check that
  the presented CN matches the title's region, `protocol_version` → the title
  wants a TLS version this server does not speak).
- **Request level** – each decrypted HTTP request is logged with client IP,
  method, path, and body size
  (`https: <ip> POST /us-gw/v2.5_others (35-byte body)`).
- **DNS** – each redirected name is logged (`dns: <name> -> <ip> (redirected)`).

Logs go to standard error; redirect them to a file or your init system as needed.

## Why a hand-rolled TLS 1.0 server

A PS2 DNAS client opens the handshake with an **SSLv2-compatible CLIENT-HELLO**:
a message wrapped in the old 2-byte SSLv2 record framing (`0x80 …`) that offers
**TLS 1.0** and `TLS_RSA_WITH_3DES_EDE_CBC_SHA` / `TLS_RSA_WITH_RC4_128_SHA`.
Two facts rule out Go's `crypto/tls`:

1. It rejects the `0x80` SSLv2 framing outright (as does modern OpenSSL 3.x) —
   this is why the original project needed a patched Apache/OpenSSL.
2. Even bridging that is not enough: the PS2 folds the **raw SSLv2 hello body**
   into its handshake-transcript hash, whereas `crypto/tls` always hashes the
   v3 `ClientHello` it parsed. The two transcripts differ, so the client's
   `Finished` MAC never verifies. This was confirmed empirically — decrypting a
   real captured `Finished` with the server private key yields
   `verify_data = 8725f58a…`, which is reproduced *only* by hashing the v2 body,
   not a canonical v3 reconstruction (see
   [`capture_test.go`](capture_test.go)).

So `dnasrep` implements just enough of TLS 1.0 itself ([`tls10.go`](tls10.go)):
the SSLv2/v3 hello, RSA key exchange, the TLS 1.0 PRF and key expansion, 3DES-CBC
records with HMAC-SHA1, and the Finished exchange — hashing the v2 body exactly
as the console does. It handles a normal v3 `ClientHello` too, so ordinary TLS
clients still work.

**Verification.** Every primitive was checked three ways: the full handshake is
driven end-to-end by a hand-written v2 client in
[`tls10_test.go`](tls10_test.go); the transcript is proven bit-for-bit against
the real PS2 capture in [`capture_test.go`](capture_test.go); and an independent
`openssl s_client -tls1 -cipher DES-CBC3-SHA` completes the handshake and
retrieves a document. The remaining unknown — as always without the exact target
hardware — is title-to-title quirks, so **test against your console**.

## Important caveats

### Cipher / protocol scope
Only TLS 1.0 with `TLS_RSA_WITH_3DES_EDE_CBC_SHA` (RSA key exchange) is
implemented, because that is what the observed PS2 negotiates. If a specific
title only offers something else (e.g. pure SSLv3, or RC4-only), the handshake
will fail with a clear log line naming the missing cipher; open an issue with a
capture and the suite can be added.

### Certificates
The server sends the leaf certificate followed by `ca-cert.pem` (the forged
VeriSign "Class 3 Public Primary CA" that signed the leaves), exactly as the
original Apache setup did via `SSLCertificateChainFile`. Titles whose DNAS
library verifies the chain need this; titles that don't ignore the extra
certificate. A missing `ca-cert.pem` only logs a warning at startup, but expect
`unknown_ca`/`bad_certificate` alerts from stricter titles without it.

The bundled certificates were **re-issued in September 2026** with
[`tools/gencerts`](tools/gencerts/main.go), keeping the original subjects and
the per-region leaf keys but fixing three things the 2016 originals (kept in
[`certs/original-2016/`](certs/original-2016)) got wrong for titles that
actually verify:

- **SHA-1 signatures instead of SHA-256.** The PS2's DNAS library embeds an
  OpenSSL of the 0.9.6/0.9.7 era (its SSLv2 hello carries that version's
  default cipher list verbatim), which does not know SHA-256. A verifying title
  could not even start checking the old leaf's signature.
- **Valid 2000-01-01 .. 2037-12-31** instead of expired since April 2026 — the
  window starts early enough for a console whose clock was never set and ends
  before the 32-bit `time_t` rollover.
- A CA self-signature with a standard OID instead of the OIW `shaWithRSA`.

Titles that never verified the certificate are unaffected. To go back to the
originals for comparison, run with `-certdir certs/original-2016` (the key
files are shared, copy them in first). To re-issue again, run
`go run ./tools/gencerts -certdir ./certs`; `certs/ca-key.pem` is the (fake)
CA's key and is versioned on purpose so the issuer stays stable.

### Certificate region selection
The PS2's SSLv2-compatible hello carries **no SNI**, so the server cannot tell
from the TLS connection itself whether a title expects the JP, EU or US
certificate — and titles that check the certificate's CN against the hostname
reject the wrong region with a `certificate_unknown` alert.

What the console does reveal is the DNS lookup: right before connecting it
resolves `gate1.<region>.dnas.playstation.org` (or `ts01.`, `bbn01.`, …).
When `dnasrep` is the console's DNS server, the redirector notes the region
per client IP (`dns: gate1.eu.dnas.playstation.org -> 192.168.2.10 (redirected,
eu region noted for 192.168.2.55)`) and the next TLS connection from that IP
gets the matching certificate (`tls: 192.168.2.55 ClientHello: …; using eu
certificate (DNS lookup 1s ago)`). Each new lookup overrides the previous
one, so switching titles just works. Requires the console to query this server
directly; if a router or forwarder sits in between, the DNS source IP is not
the console's and the hint does not match.

Without a usable hint — DNS disabled (`-dns ""`), DNS served elsewhere, or no
certificate for the resolved region — `-default-region` is used. The
multi-IP setup still works as a fallback: give the host three IPs and run one
instance per IP with the matching region, e.g.:

```sh
./dnasrep -https 192.168.2.10:443 -default-region jp -dns ""   &
./dnasrep -https 192.168.2.20:443 -default-region eu -dns ""   &
./dnasrep -https 192.168.2.30:443 -default-region us -dns :53 -redirect-ip … &
```

(Run the DNS redirector on just one of them.)

## Tests

```sh
go test ./...
```

The suite covers all the load-bearing pieces:

- `TestEncrypt3nMatchesManual` – the compact 3DES-CBC `encrypt3n` is bit-for-bit
  identical to a faithful port of the original PHP loop.
- `TestFullV2Handshake` – a hand-written SSLv2 client completes a full handshake
  (RSA kex, 3DES-CBC records, Finished both ways) and fetches a DNAS reply.
- `TestCaptureTranscriptMatchesRealPS2` – the transcript hashing reproduces a
  real console's `Finished` (skipped if the reference certs are absent).
