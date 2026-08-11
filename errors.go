package jose

import (
	"errors"
	"fmt"
)

// Sentinel errors returned by the package. Callers may test for these using
// errors.Is. Parsing, verification, and decryption errors are wrapped so that a
// single returned error can match one of these categories while still carrying
// a descriptive message.
//
// Decryption deliberately reports a single, uniform ErrDecryptFailed for every
// cryptographic failure — a bad key, a corrupt tag, or invalid padding all look
// the same to the caller — so that nothing resembling a padding oracle leaks
// out of the API.
var (
	// ErrInvalidToken is a generic error indicating a JWS or JWE could not be
	// parsed or is otherwise malformed.
	ErrInvalidToken = errors.New("jose: token is invalid")

	// ErrMalformed indicates the compact or JSON serialization did not have
	// the structure required by RFC 7515 / RFC 7516, or a part failed to
	// base64url-decode.
	ErrMalformed = errors.New("jose: token is malformed")

	// ErrSignatureInvalid indicates a JWS signature or MAC failed verification.
	ErrSignatureInvalid = errors.New("jose: signature is invalid")

	// ErrDecryptFailed indicates a JWE could not be decrypted: the key was
	// wrong, the authentication tag did not match, or the content was
	// corrupt. The cause is deliberately not distinguished.
	ErrDecryptFailed = errors.New("jose: decryption failed")

	// ErrInvalidKeyType indicates the key supplied to an algorithm was not of
	// the Go type that algorithm requires. This is the error that closes
	// algorithm-confusion attacks.
	ErrInvalidKeyType = errors.New("jose: key is of invalid type")

	// ErrInvalidKey indicates a JWK could not be decoded into a usable key, or
	// held inconsistent or out-of-range parameters.
	ErrInvalidKey = errors.New("jose: key is invalid")

	// ErrKeyNotFound indicates a JWK Set did not contain a key matching the
	// requested key ID.
	ErrKeyNotFound = errors.New("jose: no key found for kid")

	// ErrUnsupportedAlgorithm indicates the "alg" header named a signature or
	// key-management algorithm this package does not implement.
	ErrUnsupportedAlgorithm = errors.New("jose: unsupported algorithm")

	// ErrUnsupportedEncryption indicates the "enc" header named a content
	// encryption algorithm this package does not implement.
	ErrUnsupportedEncryption = errors.New("jose: unsupported content encryption algorithm")

	// ErrNoneAlgDisallowed indicates a JWS used the unsecured "none"
	// algorithm. This package never verifies such a token.
	ErrNoneAlgDisallowed = errors.New("jose: 'none' algorithm is not allowed")

	// ErrInvalidCrit indicates the JOSE "crit" header listed an extension the
	// caller has not declared as understood, or was itself malformed.
	ErrInvalidCrit = errors.New("jose: unsupported or malformed 'crit' header")

	// ErrInvalidHeader indicates a JOSE header was missing a required
	// parameter or held a parameter of the wrong JSON type.
	ErrInvalidHeader = errors.New("jose: invalid JOSE header")

	// ErrCompressionLimit indicates a "zip":"DEF" payload expanded past
	// MaxDecompressedSize, which is how this package refuses decompression
	// bombs.
	ErrCompressionLimit = errors.New("jose: decompressed payload exceeds limit")

	// ErrIterationCount indicates a PBES2 "p2c" header requested more PBKDF2
	// iterations than MaxPBES2Count permits, a denial-of-service vector when
	// the count is attacker-supplied.
	ErrIterationCount = errors.New("jose: PBES2 iteration count out of range")

	// ErrDetachedPayload indicates a compact JWS carried no payload and the
	// caller supplied none out of band. See VerifyOptions.DetachedPayload.
	ErrDetachedPayload = errors.New("jose: payload is detached")
)

// More specific sentinels for the integrity and key-usage rules. Each one wraps
// the broader category above, so a caller who tests for ErrInvalidHeader,
// ErrInvalidCrit, or ErrInvalidKey keeps matching while a caller who wants to
// know exactly which rule was broken can ask.
var (
	// ErrUnprotectedB64 indicates the RFC 7797 "b64" parameter appeared
	// somewhere other than the protected header. "b64" decides how an
	// authenticated octet string is interpreted, so RFC 7797 §6 requires it to
	// be integrity protected; honouring an unprotected copy would let anyone
	// holding a valid JWS change the payload the recipient sees.
	ErrUnprotectedB64 = fmt.Errorf("%w: 'b64' must be integrity protected", ErrInvalidHeader)

	// ErrUnprotectedCritical indicates a parameter named in "crit" was present
	// only in an unprotected header. RFC 7515 §4.1.11 makes "crit" the
	// producer's demand that the recipient honour a parameter; a demand
	// satisfied by unauthenticated data is no demand at all.
	ErrUnprotectedCritical = fmt.Errorf("%w: critical parameter is not integrity protected", ErrInvalidCrit)

	// ErrKeyUseMismatch indicates a JWK's "use" (RFC 7517 §4.2) does not permit
	// the operation, e.g. a "use":"enc" key offered for signing.
	ErrKeyUseMismatch = fmt.Errorf("%w: JWK 'use' does not permit the operation", ErrInvalidKey)

	// ErrKeyAlgMismatch indicates a JWK pinned to one algorithm by its "alg"
	// (RFC 7517 §4.4) was used with another, which is how an algorithm
	// downgrade goes unnoticed.
	ErrKeyAlgMismatch = fmt.Errorf("%w: JWK 'alg' does not permit the algorithm", ErrInvalidKey)

	// ErrKeyOpsMismatch indicates a JWK's "key_ops" (RFC 7517 §4.3) does not
	// list the operation being attempted.
	ErrKeyOpsMismatch = fmt.Errorf("%w: JWK 'key_ops' does not permit the operation", ErrInvalidKey)
)
