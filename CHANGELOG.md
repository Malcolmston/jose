# Changelog

All notable changes to this project are documented in this file. The format is
loosely based on [Keep a Changelog](https://keepachangelog.com/), and the
project aims to follow semantic versioning.

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

[0.1.0]: https://github.com/Malcolmston/jose/releases/tag/v0.1.0
