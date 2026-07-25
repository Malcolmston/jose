// Package jose is a standard-library-only implementation of the JOSE stack:
// JSON Web Signature (RFC 7515), JSON Web Encryption (RFC 7516), JSON Web Key
// (RFC 7517), and the JSON Web Algorithms they are built from (RFC 7518).
//
// # Overview
//
// JOSE is four specifications that compose: a key format (JWK), a signature
// container (JWS), an encryption container (JWE), and a registry of algorithms
// (JWA) naming what may go in the "alg" and "enc" headers. This package
// implements all four using only the Go standard library (crypto/*, encoding/*,
// compress/flate, math/big). There are no third-party dependencies and no cgo.
//
// The sibling package github.com/malcolmston/jwt covers RFC 7519 claims and the
// JWS compact serialization for tokens; this package covers the wider stack,
// including encryption, the JSON serializations, and key agreement.
//
// # Signature algorithms (JWS "alg")
//
//	HS256, HS384, HS512   HMAC-SHA2               key: []byte
//	RS256, RS384, RS512   RSASSA-PKCS1-v1_5       sign: *rsa.PrivateKey, verify: *rsa.PublicKey
//	PS256, PS384, PS512   RSASSA-PSS              sign: *rsa.PrivateKey, verify: *rsa.PublicKey
//	ES256, ES384, ES512   ECDSA on P-256/384/521  sign: *ecdsa.PrivateKey, verify: *ecdsa.PublicKey
//	EdDSA                 Ed25519                 sign: ed25519.PrivateKey, verify: ed25519.PublicKey
//
// ECDSA signatures use the fixed-width r||s encoding RFC 7518 §3.4 requires,
// not ASN.1 DER. The unsecured "none" algorithm is never verified: Verify
// rejects it with ErrNoneAlgDisallowed and there is no option to enable it.
//
// # Key management algorithms (JWE "alg")
//
//	RSA1_5                        RSAES-PKCS1-v1_5 (legacy; prefer RSA-OAEP-256)
//	RSA-OAEP                      RSAES-OAEP with SHA-1
//	RSA-OAEP-256                  RSAES-OAEP with SHA-256
//	A128KW, A192KW, A256KW        AES Key Wrap (RFC 3394)
//	dir                           the supplied symmetric key is the CEK
//	ECDH-ES                       ECDH with Concat KDF; the agreed key is the CEK
//	ECDH-ES+A128KW/+A192KW/+A256KW  ECDH-agreed key wraps the CEK
//	A128GCMKW, A192GCMKW, A256GCMKW  AES-GCM key wrapping ("iv"/"tag" headers)
//	PBES2-HS256+A128KW              PBKDF2-HMAC-SHA-256 then A128KW
//	PBES2-HS384+A192KW              PBKDF2-HMAC-SHA-384 then A192KW
//	PBES2-HS512+A256KW              PBKDF2-HMAC-SHA-512 then A256KW
//
// ECDH-ES works over P-256, P-384, P-521 (crypto/ecdh) and X25519.
//
// # Content encryption algorithms (JWE "enc")
//
//	A128CBC-HS256   AES-128-CBC + HMAC-SHA-256, 128-bit tag, 32-octet CEK
//	A192CBC-HS384   AES-192-CBC + HMAC-SHA-384, 192-bit tag, 48-octet CEK
//	A256CBC-HS512   AES-256-CBC + HMAC-SHA-512, 256-bit tag, 64-octet CEK
//	A128GCM         AES-128-GCM, 96-bit IV, 128-bit tag, 16-octet CEK
//	A192GCM         AES-192-GCM, 96-bit IV, 128-bit tag, 24-octet CEK
//	A256GCM         AES-256-GCM, 96-bit IV, 128-bit tag, 32-octet CEK
//
// # Primitives implemented here
//
// golang.org/x/crypto is not a dependency, so four primitives the standard
// library does not export are implemented directly from their specifications
// and are exported for reuse: AESKeyWrap and AESKeyUnwrap (RFC 3394), PBKDF2
// (RFC 8018 §5.2), ConcatKDF (NIST SP 800-56A in the single-hash form of
// RFC 7518 §4.6.2), and the AES-CBC-HMAC-SHA2 construction of RFC 7518 §5.2.
//
// # JWK
//
// ParseJWK decodes a single key and JWK.Key resolves it to a Go crypto key;
// FromKey is the inverse. JWK.Thumbprint computes the RFC 7638 thumbprint,
// base64url-encoded, which makes a convenient deterministic "kid". ParseJWKSet
// decodes a key set and JWKSet.LookupKeyID selects from it. A *JWK may be
// passed directly as the key to Sign, Verify, Encrypt, and Decrypt.
//
// # Signing and verifying
//
//	token, err := jose.Sign(payload, key, jose.SignOptions{Algorithm: jose.ES256})
//	payload, header, err := jose.Verify(token, publicKey)
//
// Sign produces the compact serialization; SignJSON produces the general JSON
// serialization and SignJSONMulti attaches several signatures, each with its
// own key, algorithm, and unprotected header. VerifyJSON accepts both the
// general and flattened forms and returns the first signature that verifies
// with the supplied key. VerifyWithOptions restricts the accepted algorithms,
// declares understood "crit" extensions, and supplies a detached payload.
//
// # Encrypting and decrypting
//
//	token, err := jose.Encrypt(plaintext, recipientPublicKey, jose.EncryptOptions{
//	        Algorithm:  jose.ECDH_ES_A256KW,
//	        Encryption: jose.A256GCM,
//	})
//	plaintext, header, err := jose.Decrypt(token, recipientPrivateKey)
//
// Encrypt produces the compact serialization. EncryptJSON produces the general
// JSON serialization, which can additionally carry a shared unprotected header
// and an "aad" member, and EncryptJSONMulti addresses several recipients from
// one content encryption. DecryptJSON accepts the general and flattened forms
// and tries recipients until one of them yields a usable key.
//
// # Security properties
//
// Every algorithm type-asserts the key it is handed, so a token cannot be
// verified or decrypted with a key of the wrong type — the classic
// algorithm-confusion attack. The "alg" header never selects a key on its own.
//
// All authentication tags and MACs are compared with hmac.Equal in constant
// time. CBC content decryption verifies the tag before it touches the
// ciphertext, and every cryptographic decryption failure — wrong key, bad tag,
// invalid padding — reports the same ErrDecryptFailed, so the API cannot be
// used as a padding oracle.
//
// A "crit" header naming an extension the caller has not declared as understood
// causes rejection, as RFC 7515 §4.1.11 requires. "zip":"DEF" payloads inflate
// under a cap of MaxDecompressedSize, which refuses DEFLATE bombs. The PBES2
// "p2c" iteration count is attacker-supplied, so it is bounded by
// MinPBES2Count and MaxPBES2Count before any key derivation is attempted.
//
// # Errors
//
// All errors are wrapped sentinels; test them with errors.Is, e.g.
// errors.Is(err, jose.ErrDecryptFailed) or errors.Is(err, jose.ErrInvalidCrit).
package jose
