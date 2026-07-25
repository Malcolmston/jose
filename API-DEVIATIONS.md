# API deviations from the shared contract

Every signature in the contract's section 4 (`jose`) is implemented exactly as
written. Nothing was renamed, removed, or changed in shape. What follows is a
list of **additions** — symbols the contract did not name but that the RFCs
require in order to be usable or safe — plus two behavioural decisions worth
recording.

## Additions

### JWE JSON serialization

Added by the coordinator after the initial contract; recorded here for
completeness.

```go
func EncryptJSON(plaintext []byte, key any, opts EncryptOptions) ([]byte, error)
func EncryptJSONMulti(plaintext []byte, opts EncryptOptions, recipients ...Recipient) ([]byte, error)
func DecryptJSON(data []byte, key any) (plaintext []byte, header map[string]any, err error)
type Recipient struct{ Key any; Algorithm, KeyID string; Header map[string]any }
```

RFC 7520 §5.10–§5.13 and RFC 7516 A.4/A.5 publish no compact form, so these are
the only way to reach those behaviours: the `aad` member, a shared unprotected
header, and multiple recipients over one content encryption.

### Multi-signature JWS

```go
type Signer struct{ Key any; Options SignOptions }
func SignJSONMulti(payload []byte, signers ...Signer) ([]byte, error)
```

The contract asked for "general JSON serialization with multiple signatures" but
`SignJSON` takes a single key, so producing RFC 7520 §4.8 needs this.

### Options variants

```go
type VerifyOptions struct{ Algorithms, KnownCritical []string; DetachedPayload []byte }
type DecryptOptions struct{ Algorithms, Encryptions, KnownCritical []string; MaxDecompressed int }

func VerifyWithOptions(token string, key any, opts VerifyOptions) ([]byte, map[string]any, error)
func VerifyJSONWithOptions(data []byte, key any, opts VerifyOptions) ([]byte, map[string]any, error)
func DecryptWithOptions(token string, key any, opts DecryptOptions) ([]byte, map[string]any, error)
func DecryptJSONWithOptions(data []byte, key any, opts DecryptOptions) ([]byte, map[string]any, error)
```

The contract's `Verify(token, key)` has nowhere to put three things the RFCs
require a recipient to control:

- a **detached payload** (RFC 7515 Appendix F). `SignOptions.DetachPayload` is in
  the contract, so the payload has to be supplied somewhere at verification
  time or the feature is write-only.
- the set of **understood `crit` extensions**. RFC 7515 §4.1.11 says a recipient
  must reject any critical parameter it does not understand — which means an
  application that *does* understand one needs a way to say so.
- an **allow-list of algorithms**, the standard defence against algorithm
  confusion.

`Verify`, `VerifyJSON`, `Decrypt`, and `DecryptJSON` keep the exact contract
signatures and delegate to these with the zero options.

### Exported primitives

```go
func AESKeyWrap(kek, plaintext []byte) ([]byte, error)
func AESKeyUnwrap(kek, ciphertext []byte) ([]byte, error)
func PBKDF2(password, salt []byte, iterations, keyLen int, newHash func() hash.Hash) ([]byte, error)
func ConcatKDF(z []byte, algID string, apu, apv []byte, keyLen int) ([]byte, error)
```

`golang.org/x/crypto` is not permitted, so these are implemented here from
RFC 3394, RFC 8018 §5.2, and NIST SP 800-56A / RFC 7518 §4.6.2. They are
exported because they are independently useful, independently testable against
their own specification vectors, and otherwise unavailable to a stdlib-only Go
program.

### Algorithm identifiers, registries, and limits

Named constants for every `alg`/`enc` value (`HS256`, `RSA_OAEP_256`,
`A128CBC_HS256`, …), the registry accessors `SignatureAlgorithms`,
`KeyManagementAlgorithms`, `ContentEncryptionAlgorithms`, and
`ContentEncryptionKeySize`; the `Header` map type with typed accessors; and the
security limits `MaxDecompressedSize`, `DefaultPBES2Count`, `MinPBES2Count`,
`MaxPBES2Count`, `MaxPBES2SaltInput`. The limits are exported so that callers
can see, and reason about, the bounds their inputs are held to.

### EncryptOptions fields

`Unprotected map[string]any` and `AdditionalAuthenticatedData []byte` were added
alongside the contract's fields. Both are meaningless in the compact
serialization — `Encrypt` rejects them — and both are required by RFC 7520
§5.10 and §5.11.

### JWK helper

`JWK.IsPrivate() bool`, used internally to reject an `epk` header that smuggles
in private parameters, and useful to callers publishing a JWKS.

## Behavioural decisions

### `EncryptOptions.AdditionalHeaders`

The contract lists both `Header` and `AdditionalHeaders`. Since the compact
serialization has no unprotected header, both are treated as protected header
parameters; `AdditionalHeaders` is merged after `Header`, so it wins on a
collision. Callers wanting genuinely unprotected parameters use
`Unprotected` with `EncryptJSON`.

### `RSA1_5` is supported

The contract's `alg` list does not name `RSA1_5`, but RFC 7520 §5.1 and §5.13
use it and the contract does name `crypto/rsa` PKCS1v15 among the permitted
primitives. It is implemented in both directions. Decryption uses
`rsa.DecryptPKCS1v15SessionKey` with a fixed-length session key so that invalid
padding is indistinguishable from a wrong key, and the doc comment marks the
algorithm as legacy.

### `none` has no opt-in

The sibling `jwt` port allows `none` behind two explicit opt-ins. This package
has none: `Sign` refuses to produce it and `Verify` refuses to accept it, in
every serialization. An unsecured JWS has no place in a library whose other job
is encryption.
