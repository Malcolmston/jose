# jose

The full JOSE stack for Go: **JWS** (RFC 7515), **JWE** (RFC 7516), **JWK /
JWKS** (RFC 7517), and the **JWA** algorithm registry (RFC 7518), with
conformance measured against the RFC 7520 "JOSE Cookbook" vectors. It is built
entirely on the Go standard library: no third-party modules, no cgo, no
`require` directives.

## jwt vs jose — which one do you want?

This family ships two crypto libraries. They are complements, not competitors.

| | [`github.com/malcolmston/jwt`](https://github.com/Malcolmston/jwt) | `github.com/malcolmston/jose` (this package) |
| --- | --- | --- |
| **Question it answers** | "Is this token from who it says, and is it still valid?" | "Sign, encrypt, and key-manage arbitrary JOSE objects." |
| **Specs** | RFC 7519 (JWT claims) on RFC 7515 JWS compact | RFC 7515 + **7516 + 7517 + 7518**, vectors from RFC 7520 |
| **Payload model** | Typed claims — `RegisteredClaims`, `MapClaims`, your own struct | Opaque `[]byte`. No claim model at all. |
| **Time / validation** | `exp`/`nbf`/`iat`, audience, issuer, leeway, injectable clock | None. Not its job. |
| **Serializations** | Compact only (plus RFC 7797 detached) | Compact **and** JSON (general + flattened) for both JWS and JWE |
| **Encryption (JWE)** | ✗ | ✓ — 17 `alg` × 6 `enc` combinations |
| **Multiple recipients / signatures** | ✗ | ✓ — `EncryptJSONMulti`, `SignJSONMulti` |
| **Key agreement / wrapping** | ✗ | ✓ — ECDH-ES, AES-KW, AES-GCMKW, PBES2 |
| **Compression** | ✗ | ✓ — `zip: DEF`, bounded |
| **API shape** | `Parse` / `ParseWithClaims` with a `Keyfunc`, parser options | `Sign` / `Verify` / `Encrypt` / `Decrypt` over bytes |

**Rule of thumb:** if you are issuing or checking bearer tokens for an HTTP API,
use `jwt` — it is smaller, it validates claims, and it will not let you
accidentally reach for a JWE. If you need encrypted payloads, JWE, ECDH-ES key
agreement, the JWS JSON serialization, multiple signatures over one payload, or
password-based key wrapping, use `jose`.

They overlap only in JWS signing and JWK parsing, and they share no code — each
is standalone by design. Using both in one program is fine and common: `jwt` for
the access token, `jose` for the encrypted payload it points at.

## Install

```sh
go get github.com/malcolmston/jose
```

Requires Go 1.24 or newer.

## Algorithm support

### JWS signature algorithms (`alg`)

| Family | Values | Key type | Deterministic |
| --- | --- | --- | --- |
| HMAC-SHA2 | `HS256` `HS384` `HS512` | `[]byte` | yes |
| RSASSA-PKCS1-v1_5 | `RS256` `RS384` `RS512` | `*rsa.PrivateKey` / `*rsa.PublicKey` | yes |
| RSASSA-PSS | `PS256` `PS384` `PS512` | `*rsa.PrivateKey` / `*rsa.PublicKey` | no (random salt) |
| ECDSA | `ES256` `ES384` `ES512` | `*ecdsa.PrivateKey` / `*ecdsa.PublicKey` | no (random nonce) |
| EdDSA | `EdDSA` (Ed25519) | `ed25519.PrivateKey` / `ed25519.PublicKey` | yes |
| Unsecured | `none` | — | **never accepted** |

### JWE key management (`alg`) × content encryption (`enc`)

All 17 `alg` values interoperate with all 6 `enc` values.

| `alg` (key management) | Mechanism | Key type |
| --- | --- | --- |
| `RSA1_5` | RSAES-PKCS1-v1_5 | RSA — *legacy, see Security* |
| `RSA-OAEP` | RSAES-OAEP, SHA-1 + MGF1-SHA-1 | RSA |
| `RSA-OAEP-256` | RSAES-OAEP, SHA-256 + MGF1-SHA-256 | RSA |
| `A128KW` `A192KW` `A256KW` | AES Key Wrap, RFC 3394 | `[]byte` |
| `A128GCMKW` `A192GCMKW` `A256GCMKW` | AES-GCM key wrapping (`iv`/`tag` headers) | `[]byte` |
| `dir` | Direct use of a shared symmetric CEK | `[]byte` |
| `ECDH-ES` | ECDH-ES + Concat KDF, agreed key *is* the CEK | `*ecdsa.*` / `*ecdh.*` |
| `ECDH-ES+A128KW` `+A192KW` `+A256KW` | ECDH-ES agreement, then AES-KW of the CEK | `*ecdsa.*` / `*ecdh.*` |
| `PBES2-HS256+A128KW` `-HS384+A192KW` `-HS512+A256KW` | PBKDF2 + AES-KW | password `[]byte` |

| `enc` (content encryption) | Mechanism | CEK size |
| --- | --- | --- |
| `A128CBC-HS256` | AES-128-CBC + HMAC-SHA-256, encrypt-then-MAC | 256 bits |
| `A192CBC-HS384` | AES-192-CBC + HMAC-SHA-384, encrypt-then-MAC | 384 bits |
| `A256CBC-HS512` | AES-256-CBC + HMAC-SHA-512, encrypt-then-MAC | 512 bits |
| `A128GCM` | AES-128-GCM | 128 bits |
| `A192GCM` | AES-192-GCM | 192 bits |
| `A256GCM` | AES-256-GCM | 256 bits |

Compression: `zip: DEF` (raw DEFLATE, `compress/flate`), bounded on decompress.

### Everything is standard library

The family rule is stdlib-only — **`golang.org/x/crypto` is off-limits**, and
`go.mod` carries zero `require` directives. Three primitives that a JOSE
implementation normally imports from `x/crypto` are therefore implemented by
hand in this package, from their specifications:

- **AES Key Wrap** (RFC 3394) — `keywrap.go`. The 6-round wrap/unwrap with the
  default IV `A6A6A6A6A6A6A6A6`, backing `A128KW`/`A192KW`/`A256KW` and the
  `ECDH-ES+…KW` and `PBES2-…` variants. Unwrap compares the recovered IV in
  constant time.
- **PBKDF2** (RFC 8018 §5.2) — `pbkdf2.go`. HMAC-SHA-256/384/512 PRFs, driving
  the `PBES2-*` algorithms.
- **Concat KDF** (NIST SP 800-56A §5.8.1, as profiled by RFC 7518 §4.6.2) —
  `ecdh.go`. The `AlgorithmID ‖ PartyUInfo ‖ PartyVInfo ‖ SuppPubInfo` OtherInfo
  construction over SHA-256, used by every `ECDH-ES` variant.

Everything else comes from `crypto/rsa`, `crypto/ecdsa`, `crypto/ecdh`,
`crypto/ed25519`, `crypto/aes`, `crypto/cipher`, `crypto/hmac`,
`crypto/sha256`, `crypto/sha512`, and `compress/flate`.

## Usage

### Sign and verify (JWS compact)

```go
signed, err := jose.Sign([]byte(`{"hello":"world"}`), privKey, jose.SignOptions{
    Algorithm: "ES256",
    KeyID:     "2026-07-key-1",
})

payload, header, err := jose.Verify(signed, pubKey)
// errors.Is(err, jose.ErrSignatureInvalid) / jose.ErrNoneAlgDisallowed / ...
```

### JWS JSON serialization

```go
data, err := jose.SignJSON(payload, key, jose.SignOptions{
    Algorithm:   "HS256",
    Unprotected: map[string]any{"kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037"},
})

payload, header, err := jose.VerifyJSON(data, key)
```

### Detached payload

```go
jws, _ := jose.Sign(payload, key, jose.SignOptions{
    Algorithm:     "HS256",
    DetachPayload: true, // yields "header..signature"
})
```

### Encrypt and decrypt (JWE)

```go
token, err := jose.Encrypt([]byte("Live long and prosper."), rsaPub, jose.EncryptOptions{
    Algorithm:  "RSA-OAEP-256",
    Encryption: "A256GCM",
    KeyID:      "samwise.gamgee@hobbiton.example",
    Compress:   true, // zip: DEF
})

plaintext, header, err := jose.Decrypt(token, rsaPriv)
```

### JWE JSON serialization, and encrypting to multiple recipients

The compact form addresses exactly one recipient and carries no unprotected
header. `EncryptJSON` / `EncryptJSONMulti` / `DecryptJSON` cover the general and
flattened JSON serializations, which add a shared unprotected header,
per-recipient headers, additional authenticated data, and several recipients
over one shared CEK.

```go
// One recipient, JSON serialization, with AAD and a shared unprotected header.
data, err := jose.EncryptJSON(plaintext, key, jose.EncryptOptions{
    Algorithm:                   "A128KW",
    Encryption:                  "A128GCM",
    Unprotected:                 map[string]any{"jku": "https://issuer.example/keys.jwks"},
    AdditionalAuthenticatedData: []byte(`["vcard",[...]]`),
})

// Several recipients, each under its own key-management algorithm.
data, err = jose.EncryptJSONMulti(plaintext,
    jose.EncryptOptions{Encryption: "A128CBC-HS256"},
    jose.Recipient{Algorithm: "RSA-OAEP-256", Key: rsaPub, KeyID: "2011-04-29"},
    jose.Recipient{Algorithm: "ECDH-ES+A256KW", Key: ecPub, KeyID: "peregrin.took@tuckborough.example"},
    jose.Recipient{Algorithm: "A256GCMKW", Key: sharedSecret, KeyID: "7"},
)

// Any recipient's key recovers the plaintext; the returned header describes
// the recipient that key unlocked.
plaintext, header, err := jose.DecryptJSON(data, ecPriv)
```

AAD is authenticated as `ASCII(BASE64URL(protected) ‖ '.' ‖ BASE64URL(aad))`
per RFC 7516 §5.1. Recipients are tried `kid`-first, then by trial decryption.

### Password-based encryption (PBES2)

```go
token, err := jose.Encrypt(secret, []byte("correct horse battery staple"),
    jose.EncryptOptions{
        Algorithm:  "PBES2-HS512+A256KW",
        Encryption: "A128CBC-HS256",
    })
```

### ECDH-ES key agreement

```go
token, err := jose.Encrypt(msg, recipientECPub, jose.EncryptOptions{
    Algorithm:  "ECDH-ES+A128KW",
    Encryption: "A128GCM",
    Header:     map[string]any{"apu": "QWxpY2U", "apv": "Qm9i"},
})
```

### JWK / JWKS

```go
set, err := jose.ParseJWKSet(jwksBytes)
k, ok := set.LookupKeyID("2011-04-29")
pubKey, err := k.Key()          // *rsa.PublicKey, *ecdsa.PublicKey, []byte, ...
thumb, err := k.Thumbprint()    // RFC 7638, e.g. "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

jwk, err := jose.FromKey(myEd25519Pub)
pub, err := jwk.Public()        // strips all private material
```

## Parity

Conformance is measured against the vendored RFC vector corpus, not asserted.
Run it yourself:

```sh
go test -run TestUpstreamParity -v ./...
```

**Measured: 55 of 55 synced upstream cases pass — 100%**, across 39 vendored
fixtures (RFC 7520 §3/§4/§5, RFC 7515 Appendix A, RFC 7516 Appendix A, RFC 7517
Appendix A, RFC 7638 §3.1, RFC 8037 CFRG curves, RFC 7797 `b64:false`).
Provenance, retrieval dates, licensing and which vectors were fetched versus
hand-transcribed are recorded in
[`testdata/UPSTREAM.md`](testdata/UPSTREAM.md).

| Group | Result |
| --- | --- |
| RFC 7520 §3.1–3.6 — JWK parse / key / thumbprint / public | **6/6 pass** |
| RFC 7520 §4.1–4.8 — JWS compact + JSON (RS256, PS384, ES512, HS256, detached, protected/unprotected header splits, 3 signatures) | **13/13 pass** |
| RFC 7520 §5.1–5.9 — JWE compact (RSA1_5, RSA-OAEP, PBES2, ECDH-ES+A128KW, ECDH-ES, dir, A256GCMKW, A128KW, `zip: DEF`) | **9/9 pass** |
| RFC 7520 §5.10–5.13 — JWE JSON serialization (`aad`, header splits, 3 recipients) | **4/4 pass** |
| RFC 7515 A.1–A.5 compact, A.6–A.7 JSON | **7/7 pass** |
| RFC 7516 A.1–A.3 compact | **3/3 pass** |
| RFC 7516 A.4–A.5 JWE JSON serialization | **2/2 pass** |
| RFC 7517 A.1–A.3 JWK Sets | **3/3 pass** |
| RFC 7638 §3.1 thumbprint | **1/1 pass** |
| RFC 8037 — Ed25519 JWS, X25519 ECDH-ES | **4/4 pass** |
| RFC 7797 — `b64:false` unencoded payload | **3/3 pass** |

### Read that number carefully

100% means *every vector in the synced corpus passes*, not *this library
implements all of JOSE*. The corpus is bounded, and these are deliberately
outside it:

1. **RFC 7520 §6 — nesting a JWS inside a JWE.** No nesting helper ships, so
   there is no API to drive the vector through. Compose `Encrypt` over `Sign`
   yourself.
2. **RFC 7517 Appendix B/C — `x5c`/`x5t` X.509 chains and PBES2-encrypted
   JWKs.** Not implemented; out of scope for v0.
3. **Encrypt-side reproduction of any JWE vector.** Impossible by construction:
   the CEK and IV are freshly random per encryption, so no correct
   implementation can reproduce a published ciphertext. Every JWE vector is
   asserted decrypt-side.
4. **Byte-for-byte re-signing for PS\* and ES\*.** RSASSA-PSS salts and ECDSA
   draws a fresh nonce, so re-signing cannot reproduce the RFC's octets; those
   are verify-only by mathematics rather than by omission. (HS\*, RS\* and
   EdDSA *are* re-signed and compared byte-for-byte.) Where an RFC's protected
   header is not canonically serialized — RFC 7515 A.1 embeds a CRLF and
   padding spaces inside the header JSON — the byte comparison is skipped and
   logged, since no re-serializer can reproduce those octets either.

Two defects in the upstream fixtures are worked around rather than silently
absorbed, both documented in `testdata/UPSTREAM.md`: the RFC 7520 §5.13
fixture's `input.enc` reads `A128CBC-H256` (contradicted by its own protected
header), and the RFC 7797 compact fixture's `signing.protected_b64u` decodes to
invalid JSON. The vendored files are kept byte-verbatim at the pinned commit.

Previously-closed gaps are tracked in `parity.json` (`gapsFound: 6`,
`gapsClosed: 6`) — all six were the JWE JSON serialization being unreachable
before `DecryptJSON` existed.

## Security

- **Algorithm-confusion defense.** Every algorithm type-asserts its key before
  use, so an attacker cannot resubmit an RSA-signed token as `HS256` with the
  public key as the HMAC secret; the mismatch surfaces as `ErrInvalidKeyType`.
  The unsecured `none` algorithm is *never* verified — there is no opt-in —
  and returns `ErrNoneAlgDisallowed`.
- **Constant-time tags and unwraps.** JWS MAC comparison, JWE authentication-tag
  comparison, AES-CBC-HMAC verification, and the AES Key Wrap integrity check
  all use `crypto/hmac.Equal` / `crypto/subtle`. CBC content encryption is
  encrypt-then-MAC per RFC 7518 §5.2, and the MAC is checked *before* any
  padding is examined.
- **No padding oracle.** Every cryptographic decryption failure — wrong key, bad
  tag, invalid PKCS#7 padding — collapses to a single `ErrDecryptFailed` with an
  identical message, so nothing distinguishing leaks to the caller.
- **Bounded decompression.** `zip: DEF` is a compression bomb vector: a few
  hundred ciphertext bytes can inflate to gigabytes. Decompression stops at
  `MaxDecompressedSize` (16 MiB by default, overridable per call via
  `DecryptOptions.MaxDecompressed`).
- **`p2c` caps.** The PBES2 iteration count arrives inside an attacker-supplied
  header, so an unbounded value is a free denial-of-service. Counts are range
  checked *before* any PBKDF2 work is done: `MinPBES2Count` (1 000) to
  `MaxPBES2Count` (1 000 000), defaulting to `DefaultPBES2Count` (100 000) when
  encrypting.
- **`crit` handling.** Critical header parameters the caller has not declared as
  understood are rejected (`ErrInvalidCrit`), per RFC 7515 §4.1.11.
- **`RSA1_5` is supported but discouraged.** It is present only because RFC 7520
  §5.1 and RFC 7516 A.2 use it and interop with old deployments requires it. It
  is vulnerable to Bleichenbacher-style adaptive chosen-ciphertext attacks and
  is deprecated by RFC 8725 §3.5. Use `RSA-OAEP-256` for anything new, and pin
  accepted algorithms on the decrypt side.

Always pin the algorithms you accept. Never let an inbound token's own `alg`
header choose which key or which primitive you use.

## License

MIT — see [LICENSE](LICENSE).

This is an independent, clean-room re-implementation of the JOSE specifications
in Go. It is **not affiliated with, endorsed by, or derived from
[panva/jose](https://github.com/panva/jose)**, whose behavior it mirrors as a
parity target. The vendored conformance vectors under `testdata/` are
third-party material under their own licenses; see
[`testdata/UPSTREAM.md`](testdata/UPSTREAM.md).
