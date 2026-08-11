# Changelog

All notable changes to this project are documented in this file. The format is
loosely based on [Keep a Changelog](https://keepachangelog.com/), and the
project aims to follow semantic versioning.

## [0.2.0] - 2026-08-11

This is a **security release**. It fixes five published advisories against
`<= 0.1.0`, all of them reachable through the public API:

| Advisory | Severity | Issue |
| --- | --- | --- |
| GHSA-4689-9mp2-q5rm | high | `crit` satisfiable from an attacker-supplied unprotected header, defeating RFC 7515 §4.1.11 processing |
| GHSA-657x-hc2h-j7mj | medium | unprotected `{"b64":false}` allows keyless payload substitution in a verified JWS |
| GHSA-w4qr-w6rh-v2mx | medium | JWK `alg` pinning not enforced: silent algorithm downgrade |
| GHSA-qvw9-rcpm-hhmw | low | JWK `use` not enforced: a `"use":"enc"` key signs and verifies a JWS |
| GHSA-89qh-5q5j-xrx9 | low | JWK `key_ops` not enforced: an encrypt/decrypt-only key signs and verifies a JWS |

**Everyone on 0.1.0 should upgrade.** Read the *Breaking changes* section below
first: three of the five fixes are enforcement of rules the RFCs always stated,
so key and algorithm combinations that 0.1.0 accepted are now errors. That is
the fix, not a side effect of it.

### Breaking changes

All of these reject input that 0.1.0 accepted. None of them change a signature,
a serialization, or the shape of any API.

- **A JWK's `alg`, `use`, and `key_ops` are now enforced on every sign, verify,
  encrypt, and decrypt** (RFC 7517 §4.2–§4.4). A key pinned to `"alg":"HS512"`
  can no longer be used with `HS256`; a `"use":"enc"` key can no longer sign or
  verify a JWS, and a `"use":"sig"` key can no longer encrypt or decrypt a JWE;
  a `key_ops` that does not list the operation refuses it. Keys that state none
  of the three remain unrestricted, and `JWK.Alg` continues to supply the
  default algorithm when `SignOptions.Algorithm` is empty. Applications relying
  — knowingly or not — on a key being usable outside its declared purpose must
  either widen the key's declaration or use the right key. New sentinels:
  `ErrKeyAlgMismatch`, `ErrKeyUseMismatch`, `ErrKeyOpsMismatch`, each wrapping
  `ErrInvalidKey`.
- **A parameter named in `crit` must now be present in the *protected* header.**
  A JWS or JWE whose critical parameter lives in a shared unprotected or
  per-signature/per-recipient header is rejected with `ErrUnprotectedCritical`
  (which wraps `ErrInvalidCrit`) on verification, and `Sign`, `SignJSON`,
  `Encrypt`, and `EncryptJSON` refuse to produce one.
- **`b64` must be in the protected header.** A `b64` anywhere else is
  `ErrUnprotectedB64` (wrapping `ErrInvalidHeader`) rather than an input, on
  both production and verification. Upstream `jose@5.9.6` silently ignores an
  unprotected `b64` instead; this package rejects the document, so the
  disagreement is visible rather than implicit. See `API-DEVIATIONS.md`.

### Security

- **`crit` can no longer be satisfied by an unprotected header**
  (GHSA-4689-9mp2-q5rm, high). `checkCritical` looked its names up in the
  *merged* protected-plus-unprotected header. `crit` is how a producer says
  "reject this unless you honour parameter X"; satisfying it from a header no
  signature covers let an attacker supply both the value and the proof that it
  was required. Combined with `b64` below, this reached the payload-substitution
  primitive even on tokens whose signer had defended against it by naming `b64`
  in `crit`. Both `crit` and the parameters it names are now read from the
  protected header only, on production as well as on verification.
- **JWK `alg`, `use`, and `key_ops` are enforced** (GHSA-w4qr-w6rh-v2mx,
  GHSA-qvw9-rcpm-hhmw, GHSA-89qh-5q5j-xrx9). 0.1.0 parsed all three and read
  none of them, so a key's own statement of what it was for had no effect: an
  `HS512`-pinned key was used with `HS256`, and an `"enc"` or
  `key_ops:["encrypt","decrypt"]` key signed and verified a JWS. These are
  defence-in-depth failures rather than signature bypasses — the correct key is
  still required — but they are the only machine-checkable statement of intent
  that travels *with* a key, and the checks that survive a caller who forgot to
  pass an algorithm allow-list.
- **JWS: `b64` is no longer honoured from an unprotected header**
  (GHSA-657x-hc2h-j7mj, medium). A `"b64":false` placed in a per-signature or
  flattened unprotected header changed the payload
  `VerifyJSON` returned — from the decoded octets to the base64url text — while
  the signature still verified, because `b64` does not enter the signing input.
  A caller who signed `{"amount":1}` could be handed `eyJhbW91bnQiOjF9` instead.
  `b64` is now read from the protected header only and must be listed in `crit`
  (RFC 7797 §3, §6); a copy anywhere else is `ErrUnprotectedB64`.
- **JWS: an empty HMAC secret no longer verifies.** `Sign` had always rejected a
  zero-length secret, but `verify` did not: HMAC keyed with zero octets is a
  public function, so anyone could compute a tag that `hmac.Equal` accepted. A
  secret that resolved to nothing — an unset environment variable, a truncated
  config value — accepted every forged token while the system looked healthy.
  Both directions now return `ErrInvalidKey`.
- **JWE JSON: `zip` is no longer honoured from an unprotected header**, for the
  same reason as `b64` — it decides how authenticated plaintext is
  post-processed.
- **`DecodeSegment` is now strict and canonical.** Padding, `+`/`/`, embedded
  whitespace or newlines, and a final quantum with non-zero unused bits are
  rejected. Previously each value had several accepted spellings, which made the
  serialized token malleable: a 64-octet ECDSA signature has four spare bits and
  so sixteen distinct tokens that all verified.
- **JWS JSON: mixed general and flattened forms are rejected**, and an empty or
  absent signature segment is refused before it reaches any primitive.
- **`p2c` is range-checked before conversion.** A `"p2c":1e300` reached an
  out-of-range `float64`→`int` conversion, which Go leaves
  implementation-defined.

### Fixed

- **`EncryptJSON` now honours caller-supplied algorithm inputs.**
  `EncryptJSONMulti` handed the key-management algorithm a header containing
  only the per-recipient parameters and merged the protected header in
  afterwards. With a single recipient that had two consequences. An explicit
  PBES2 `p2s`/`p2c` or AESGCMKW `iv` was echoed back by the algorithm and the
  merge then rejected it as a repeated header parameter, so those calls could
  not be made at all. Worse, ECDH-ES `apu`/`apv` were invisible to the Concat
  KDF, so the CEK was derived without the PartyInfo the emitted header
  advertised and the resulting document decrypted to nothing — silently, at the
  recipient. The algorithm now reads its inputs from and writes its outputs
  into one header, exactly as the compact `Encrypt` does.
- **Producer-side counterparts for the checks the consumer makes.** A one-sided
  check still rejects the document, but at the far end of the wire, long after
  the producer has discarded the inputs that caused it. `Sign`, `Encrypt` and
  `EncryptJSONMulti` now validate `crit` the way `Verify` and `Decrypt` do —
  including a `crit` supplied through `Header` rather than `SignOptions.Critical`
  — reject a header parameter repeated across the protected and unprotected
  halves, and reject a per-recipient `zip`. `encryptKeyPBES2` now enforces the
  same `[8, MaxPBES2SaltInput]` bound on `p2s` that `decryptKeyPBES2` has always
  enforced.
- Both `testdata/rfc7797/` fixtures carried a `"b64"` that was not listed in
  `"crit"`, contradicting RFC 7797 §3, and `b64_false_compact.json`'s
  `signing.protected_b64u` decoded to invalid JSON. Corrected in place to the
  values RFC 7797 §4.2 publishes; see `testdata/UPSTREAM.md`.

### Added

- `security_test.go`: 25 adversarial tests covering algorithm confusion in both
  directions, `none` on every path, empty and truncated keys, tags and
  signatures, canonical base64url and signature malleability, JWK usage
  restrictions and private-material hygiene, ECDH invalid-curve and
  point-at-infinity `epk` values, AEAD tag and AAD coverage across all six `enc`
  algorithms, per-message randomness of IVs, CEKs, ephemeral keys and PBES2
  salts, and `p2c`/`p2s` bounds.
- `example_test.go`: 14 runnable `Example` functions covering signing and
  verification, algorithm pinning, detached payloads, multi-signature JWS,
  compact and JSON JWE, ECDH-ES, PBES2, JWK conversion and thumbprints, JWK Set
  lookup by `kid`, and the decompression bound.
- `UseSig` and `UseEnc` constants for the RFC 7517 §4.2 `use` values.
- `advisory_test.go`: one regression test per published advisory, written
  against the fixed key and the fixed document each advisory publishes, plus the
  positive counterparts — a `crit` in the protected header still verifies, a key
  whose `alg`/`use`/`key_ops` match still signs and verifies, and an
  unrestricted key still round-trips in both serializations. Every negative test
  in the file fails on 0.1.0.
- `ErrUnprotectedB64`, `ErrUnprotectedCritical`, `ErrKeyUseMismatch`,
  `ErrKeyAlgMismatch`, and `ErrKeyOpsMismatch`, so a caller can tell which rule
  was broken. Each wraps the broader sentinel it belongs to.
- `producer_guard_test.go`: 8 tests holding the producer to the consumer's
  rules — unsatisfiable `crit` on both the JWS and JWE sides, repeated header
  parameters, per-recipient `zip`, PBES2 salt bounds at both ends including the
  boundary case, and the caller-supplied-algorithm-input round trips above.
- `constanttime_test.go`: a test pinning the property that makes the package's
  three constant-time comparisons safe — that none can be reached with two
  empty operands, which both `subtle.ConstantTimeCompare` and `hmac.Equal`
  report as equal. It walks the attacker's side of each comparison with an
  all-empty forgery.

## [0.1.0] - 2026-07-24

Initial release. A standard-library-only implementation of the JOSE suite —
JWS, JWE, JWK and JWA — complementing the family's `jwt` port, which covers
RFC 7519 claims over JWS compact only. No third-party modules, no cgo, and
`go.mod` carries zero `require` directives.

### Added

- **JWS (RFC 7515)**: `Sign` (compact), `SignJSON` (general JSON
  serialization), `Verify`, and `VerifyJSON`, plus their `*WithOptions` forms.
  Signature algorithms: `HS256/384/512`, `RS256/384/512`, `PS256/384/512`,
  `ES256/384/512` (fixed-width `r‖s`) and `EdDSA` (Ed25519). Supports
  per-signature protected and unprotected headers, multiple signatures over one
  payload, `crit` handling, and RFC 7797-style detached payloads
  (`SignOptions.DetachPayload`). The unsecured `none` algorithm is never
  verified.
- **JWE (RFC 7516)**: `Encrypt` and `Decrypt` over the compact serialization,
  plus `EncryptJSON`, `EncryptJSONMulti`, `DecryptJSON` and
  `DecryptJSONWithOptions` over the general and flattened JSON serializations —
  with a shared unprotected header (`EncryptOptions.Unprotected`), additional
  authenticated data (`EncryptOptions.AdditionalAuthenticatedData`), and
  several `Recipient`s sharing one CEK.
  - Key management (`alg`): `RSA1_5`, `RSA-OAEP`, `RSA-OAEP-256`,
    `A128KW`/`A192KW`/`A256KW`, `A128GCMKW`/`A192GCMKW`/`A256GCMKW`, `dir`,
    `ECDH-ES`, `ECDH-ES+A128KW`/`+A192KW`/`+A256KW`, and
    `PBES2-HS256+A128KW`/`-HS384+A192KW`/`-HS512+A256KW`.
  - Content encryption (`enc`): `A128CBC-HS256`, `A192CBC-HS384`,
    `A256CBC-HS512`, `A128GCM`, `A192GCM`, `A256GCM`.
  - `zip: DEF` compression via `compress/flate`, bounded on decompression by
    `MaxDecompressedSize` (16 MiB) or `DecryptOptions.MaxDecompressed`.
- **JWK / JWKS (RFC 7517)**: `ParseJWK`, `ParseJWKSet`, `JWK.Key`,
  `JWK.Public`, `JWK.IsPrivate`, `FromKey`, and `JWKSet.LookupKeyID` for RSA,
  EC (P-256/384/521), OKP (Ed25519) and `oct` keys. `JWK.Thumbprint` implements
  RFC 7638.
- **JWA primitives implemented by hand**, because the family's stdlib-only rule
  puts `golang.org/x/crypto` off-limits: AES Key Wrap (RFC 3394), PBKDF2
  (RFC 8018 §5.2) and Concat KDF (NIST SP 800-56A, as profiled by RFC 7518
  §4.6.2). Also exported: `SignatureAlgorithms`, `KeyManagementAlgorithms`,
  `ContentEncryptionAlgorithms`, `ContentEncryptionKeySize`.
- **Wrapped sentinel errors** for `errors.Is`: `ErrInvalidToken`,
  `ErrMalformed`, `ErrSignatureInvalid`, `ErrDecryptFailed`,
  `ErrInvalidKeyType`, `ErrInvalidKey`, `ErrKeyNotFound`,
  `ErrUnsupportedAlgorithm`, `ErrUnsupportedEncryption`,
  `ErrNoneAlgDisallowed`, `ErrInvalidCrit`, `ErrIterationCount`.

### Security

- Every algorithm type-asserts its key, closing algorithm-confusion attacks
  (`ErrInvalidKeyType`); `alg: none` is rejected unconditionally.
- CBC-HMAC content encryption is encrypt-then-MAC per RFC 7518 §5.2, with
  constant-time tag comparison performed before padding is inspected.
- All cryptographic decryption failures collapse to a single, uniform
  `ErrDecryptFailed`, so no padding oracle leaks through the API.
- The attacker-supplied PBES2 `p2c` iteration count is range-checked before any
  PBKDF2 work is performed (`MinPBES2Count` 1 000 … `MaxPBES2Count` 1 000 000,
  `DefaultPBES2Count` 100 000).
- `zip: DEF` decompression is bounded against compression bombs.

### Parity

- Vendored the upstream conformance corpus under `testdata/`: the RFC 7520
  "JOSE Cookbook" vectors from `github.com/ietf-jose/cookbook` @ `13692b68bfc1`
  (§3 JWK, §4 JWS, §5 JWE), the same repository's CFRG-curve (RFC 8037) and
  `b64:false` (RFC 7797) vectors, plus hand-transcribed vectors from RFC 7515
  Appendix A, RFC 7516 Appendix A, RFC 7517 Appendix A and RFC 7638 §3.1.
  Provenance, retrieval dates and licensing are recorded in
  `testdata/UPSTREAM.md`.
- `upstream_parity_test.go` drives 55 upstream cases through the exported API.
  **Measured: 55/55 pass (100%)** — of the synced corpus. RFC 7520 §6 (nested
  JWS-in-JWE), RFC 7517 Appendix B/C (`x5c`, encrypted JWKs) and encrypt-side
  reproduction of JWE ciphertext are deliberately outside that corpus; see the
  README's Parity section.
- Six gaps found and closed during development, all one root cause: the JWE
  JSON serialization was initially unreachable (no `DecryptJSON`), so RFC 7520
  §5.10–§5.13 and RFC 7516 A.4–A.5 — which publish no compact form — could not
  be exercised. Adding the JSON surface closed all six, along with
  multi-recipient JWE and the JWE `aad` member.

[0.2.0]: https://github.com/Malcolmston/jose/releases/tag/v0.2.0
[0.1.0]: https://github.com/Malcolmston/jose/releases/tag/v0.1.0
