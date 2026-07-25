# Upstream conformance vectors

Everything under `testdata/` is third-party conformance data, vendored so the
parity harness (`upstream_parity_test.go`) runs offline and deterministically.
Retrieval date for every item below: **2026-07-24**.

Nothing here is original to this repository. See the licensing notes per source.

---

## 1. `testdata/rfc7520/` — RFC 7520 "JOSE Cookbook"

**Machine-readable source (preferred, fetched verbatim):**

- Repository: <https://github.com/ietf-jose/cookbook>
- Commit SHA: `13692b68bfc18b99557a5b1ed311fd5077bfff04`
  (committed 2016-11-12)
- Retrieved: 2026-07-24 via `git clone --depth 1`
- License: **Unlicense** (public domain dedication). A verbatim copy of the
  repository's `LICENSE` is vendored alongside the data as
  `testdata/rfc7520/LICENSE.cookbook`.

**Normative text source (used to cross-check and to name sections):**

- <https://www.rfc-editor.org/rfc/rfc7520.txt> — RFC 7520, "Examples of
  Protecting Content Using JavaScript Object Signing and Encryption (JOSE)",
  M. Miller, May 2015.

Vendored files (copied byte-for-byte from the cookbook repository):

| Path | RFC 7520 section |
| --- | --- |
| `rfc7520/jwk/3_1.ec_public_key.json` | §3.1 |
| `rfc7520/jwk/3_2.ec_private_key.json` | §3.2 |
| `rfc7520/jwk/3_3.rsa_public_key.json` | §3.3 |
| `rfc7520/jwk/3_4.rsa_private_key.json` | §3.4 |
| `rfc7520/jwk/3_5.symmetric_key_mac_computation.json` | §3.5 |
| `rfc7520/jwk/3_6.symmetric_key_encryption.json` | §3.6 |
| `rfc7520/jws/4_1.rsa_v15_signature.json` | §4.1 |
| `rfc7520/jws/4_2.rsa-pss_signature.json` | §4.2 |
| `rfc7520/jws/4_3.ecdsa_signature.json` | §4.3 |
| `rfc7520/jws/4_4.hmac-sha2_integrity_protection.json` | §4.4 |
| `rfc7520/jws/4_5.signature_with_detached_content.json` | §4.5 |
| `rfc7520/jws/4_6.protecting_specific_header_fields.json` | §4.6 |
| `rfc7520/jws/4_7.protecting_content_only.json` | §4.7 |
| `rfc7520/jws/4_8.multiple_signatures.json` | §4.8 |
| `rfc7520/jwe/5_1.key_encryption_using_rsa_v15_and_aes-hmac-sha2.json` | §5.1 |
| `rfc7520/jwe/5_2.key_encryption_using_rsa-oaep_with_aes-gcm.json` | §5.2 |
| `rfc7520/jwe/5_3.key_wrap_using_pbes2-aes-keywrap_with-aes-cbc-hmac-sha2.json` | §5.3 |
| `rfc7520/jwe/5_4.key_agreement_with_key_wrapping_using_ecdh-es_and_aes-keywrap_with_aes-gcm.json` | §5.4 |
| `rfc7520/jwe/5_5.key_agreement_using_ecdh-es_with_aes-cbc-hmac-sha2.json` | §5.5 |
| `rfc7520/jwe/5_6.direct_encryption_using_aes-gcm.json` | §5.6 |
| `rfc7520/jwe/5_7.key_wrap_using_aes-gcm_keywrap_with_aes-cbc-hmac-sha2.json` | §5.7 |
| `rfc7520/jwe/5_8.key_wrap_using_aes-keywrap_with_aes-gcm.json` | §5.8 |
| `rfc7520/jwe/5_9.compressed_content.json` | §5.9 |
| `rfc7520/jwe/5_10.including_additional_authentication_data.json` | §5.10 |
| `rfc7520/jwe/5_11.protecting_specific_header_fields.json` | §5.11 |
| `rfc7520/jwe/5_12.protecting_content_only.json` | §5.12 |
| `rfc7520/jwe/5_13.encrypting_to_multiple_recipients.json` | §5.13 |

The cookbook's `curve25519/` and `rfc7797/` directories are vendored separately
under `testdata/rfc8037/` and `testdata/rfc7797/` — see sections 7 and 8 below.
`6.nesting_signatures_and_encryption.json` (RFC 7520 §6, a JWS nested inside a
JWE) was **not** vendored: this port ships no nesting helper, so there is no API
to drive it through.

### Known defect in the vendored `5_13` fixture

`rfc7520/jwe/5_13.encrypting_to_multiple_recipients.json` carries
`"input": {"enc": "A128CBC-H256"}` — a typo. That same vector's own protected
header decodes to `{"enc":"A128CBC-HS256"}`, and the string `A128CBC-H256`
appears nowhere in the RFC 7520 text. The fixture is deliberately kept
byte-verbatim at the pinned commit rather than patched, so the harness corrects
the value at load time; see the comment in `parityRFC7520JWE`.

---

## 2. `testdata/rfc7515/` — RFC 7515 Appendix A (JWS examples)

**Hand-transcribed** from <https://www.rfc-editor.org/rfc/rfc7515.txt>
(RFC 7515, "JSON Web Signature (JWS)", Jones/Bradley/Sakimura, May 2015).
The RFC ships these examples as prose with display line breaks inside base64url
values; there is no machine-readable release, so each value was un-wrapped and
placed into JSON by hand.

- `rfc7515/jws_compact.json` — appendices A.1 (HS256), A.2 (RS256),
  A.3 (ES256 P-256), A.4 (ES512 P-521), A.5 (`alg: none`). Each entry carries
  the RFC's JWK, the base64url payload, the complete compact serialization, and
  a `deterministic` flag (true only where re-signing must reproduce the RFC's
  exact signature octets).
- `rfc7515/jws_json.json` — appendices A.6 (general JWS JSON serialization,
  two signatures) and A.7 (flattened JWS JSON serialization).

**Transcription self-check** (run at vendoring time, independently of this Go
package, with Python's `hmac`/`hashlib` and raw modular exponentiation):

- A.1: `HMAC-SHA256(k, header || '.' || payload)` reproduces the RFC signature. ✓
- A.2: `sig^e mod n` yields an EMSA-PKCS1-v1_5 block ending in the SHA-256
  digest of the signing input. ✓
- A.3 / A.4: the EC public points satisfy the P-256 / P-521 curve equation. ✓

---

## 3. `testdata/rfc7516/` — RFC 7516 Appendix A (JWE examples)

**Hand-transcribed** from <https://www.rfc-editor.org/rfc/rfc7516.txt>
(RFC 7516, "JSON Web Encryption (JWE)", Jones/Hildebrand, May 2015), same
reasoning as above.

- `rfc7516/jwe_compact.json` — appendices A.1 (`RSA-OAEP` + `A256GCM`),
  A.2 (`RSA1_5` + `A128CBC-HS256`), A.3 (`A128KW` + `A128CBC-HS256`).
- `rfc7516/jwe_json.json` — appendices A.4 (general JWE JSON serialization,
  two recipients) and A.5 (flattened JWE JSON serialization).

**Transcription self-check:** for both RSA private keys, `p * q == n` and
`d mod (p-1) == dp`. ✓

---

## 4. `testdata/rfc7517/` — RFC 7517 Appendix A (JWK examples)

**Hand-transcribed** from <https://www.rfc-editor.org/rfc/rfc7517.txt>
(RFC 7517, "JSON Web Key (JWK)", Jones, May 2015).

- `rfc7517/a1_public_keys.json` — Appendix A.1, public JWK Set (EC P-256 + RSA).
- `rfc7517/a2_private_keys.json` — Appendix A.2, private JWK Set (EC P-256 + RSA
  with all CRT parameters).
- `rfc7517/a3_symmetric_keys.json` — Appendix A.3, symmetric JWK Set
  (`A128KW` oct key + the HMAC oct key used by RFC 7515 Appendix A.1).

Appendix B (`x5c` X.509 certificate chain) and Appendix C (encrypted RSA
private key, PBES2) were **not** vendored: `x5c` and JWE-encrypted JWKs are
outside the v0 API surface in the family contract.

**Transcription self-check:** RSA `p * q == n`; the EC point satisfies the P-256
curve equation. ✓

---

## 5. `testdata/rfc7638/` — RFC 7638 §3.1 (JWK Thumbprint)

**Hand-transcribed** from <https://www.rfc-editor.org/rfc/rfc7638.txt>
(RFC 7638, "JSON Web Key (JWK) Thumbprint", Jones/Sakimura, September 2015).

- `rfc7638/thumbprint.json` — the §3.1 RSA JWK, the canonical intermediate JSON
  object the RFC constructs, and the expected thumbprint
  `NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`.

**Transcription self-check:** `base64url(SHA-256(canonical))` equals the RFC's
published thumbprint. ✓

---

## 6. RFC 7518 (JWA)

RFC 7518 <https://www.rfc-editor.org/rfc/rfc7518.txt> supplies the algorithm
definitions (AES Key Wrap, AES-CBC-HMAC-SHA2, Concat KDF, PBES2) but its
appendices contain no additional end-to-end serializations beyond those already
covered by RFC 7515/7516 Appendix A and RFC 7520. It is cited by the harness for
algorithm semantics only; no vectors were vendored from it.

---

## 7. `testdata/rfc8037/` — CFRG curves (Ed25519, X25519)

**Fetched** verbatim from the same cookbook clone and commit as section 1
(`13692b68bfc18b99557a5b1ed311fd5077bfff04`, Unlicense), from its `curve25519/`
directory. These exercise RFC 8037, "CFRG Elliptic Curve Diffie-Hellman (ECDH)
and Signatures in JOSE" (<https://www.rfc-editor.org/rfc/rfc8037.txt>).

| Vendored path | Cookbook source | Covers |
| --- | --- | --- |
| `rfc8037/ed25519_jws.json` | `curve25519/jws.json` | `EdDSA` over an OKP/Ed25519 key; compact + general + flattened JSON |
| `rfc8037/x25519_ecdh-es.json` | `curve25519/ecdh-es.json` | `ECDH-ES` + `A128GCM` over an OKP/X25519 key |

Ed25519 signatures are deterministic (RFC 8032 derives the nonce from the key
and message), so the Ed25519 vector is asserted with a byte-for-byte re-sign in
addition to verification. The X25519 vector is decrypt-side only — its ephemeral
key and IV were random at authoring time.

## 8. `testdata/rfc7797/` — JWS Unencoded Payload Option (`"b64": false`)

**Fetched** verbatim from the same cookbook clone and commit, from its
`rfc7797/` directory. These exercise RFC 7797, "JSON Web Signature (JWS)
Unencoded Payload Option" (<https://www.rfc-editor.org/rfc/rfc7797.txt>).

| Vendored path | Cookbook source | Covers |
| --- | --- | --- |
| `rfc7797/b64_false_compact.json` | `rfc7797/hmac-sha2_b64_false.json` | `b64:false` payload that is still compact-serializable |
| `rfc7797/b64_false_json_only.json` | `rfc7797/4.2.hmac-sha2_b64_false.json` | `b64:false` payload (`$.02`) that is JSON-only |

With `b64:false` the payload enters the signing input raw rather than
base64url-encoded, and `"b64"` must appear in `"crit"` — so these vectors also
exercise critical-header handling, and are driven through
`VerifyWithOptions`/`VerifyJSONWithOptions` with `KnownCritical: ["b64"]`.

Note: `b64_false_compact.json` contains a second upstream defect — its
`signing.protected_b64u` (`...ImI2NCI6LCJjcml0...`) decodes to invalid JSON with
the `false` literal missing. The harness does not read that member; it verifies
`output.compact` and `output.json`, whose protected headers are well-formed.

---

## Licensing and attribution

- **RFCs 7515, 7516, 7517, 7518, 7520, 7638** are © IETF Trust and the persons
  identified as the document authors. Code Components extracted from these
  documents — which is what the vectors here are — are licensed under the
  **Simplified BSD License** as described in Section 4.e of the
  [IETF Trust Legal Provisions](https://trustee.ietf.org/license-info).
- **github.com/ietf-jose/cookbook** is released into the public domain under the
  **Unlicense**; its `LICENSE` is vendored at
  `testdata/rfc7520/LICENSE.cookbook`.

None of these licenses are affected by this repository's own MIT license, which
covers only the Go source.

## Summary: fetched vs. hand-transcribed

| Directory | Provenance |
| --- | --- |
| `rfc7520/` | **Fetched** verbatim (git clone, pinned SHA) |
| `rfc8037/` | **Fetched** verbatim (same clone, `curve25519/`) |
| `rfc7797/` | **Fetched** verbatim (same clone, `rfc7797/`) |
| `rfc7515/` | **Hand-transcribed** from the RFC text, self-checked |
| `rfc7516/` | **Hand-transcribed** from the RFC text, self-checked |
| `rfc7517/` | **Hand-transcribed** from the RFC text, self-checked |
| `rfc7638/` | **Hand-transcribed** from the RFC text, self-checked |
