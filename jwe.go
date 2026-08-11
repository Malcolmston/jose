package jose

import (
	"bytes"
	"compress/flate"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"
	"strings"
)

// MaxDecompressedSize bounds the plaintext a "zip":"DEF" JWE may expand to.
// DEFLATE reaches ratios above 1000:1, so an unbounded inflate is a
// straightforward memory-exhaustion attack; decompression past this limit
// fails with ErrCompressionLimit.
const MaxDecompressedSize = 16 << 20 // 16 MiB

// EncryptOptions configures the production of a JWE (RFC 7516).
type EncryptOptions struct {
	// Algorithm is the JWE key management "alg" value, e.g. "RSA-OAEP-256",
	// "A128KW", "dir", or "ECDH-ES+A256KW". When empty, Encrypt infers a
	// conventional algorithm for the key's type.
	Algorithm string

	// Encryption is the content encryption "enc" value, e.g. "A256GCM" or
	// "A128CBC-HS256". It defaults to A256GCM.
	Encryption string

	// KeyID, when non-empty, is written to the protected "kid" header.
	KeyID string

	// Header holds additional protected header parameters. Algorithm inputs
	// may be supplied here — "apu"/"apv" for ECDH-ES, "p2s"/"p2c" for
	// PBES2 — and algorithm outputs ("epk", "iv", "tag", and the generated
	// "p2s"/"p2c") are written back into the protected header.
	Header map[string]any

	// AdditionalHeaders holds further protected header parameters, merged
	// after Header. The compact serialization has no unprotected header, so
	// both maps end up protected and covered by the authentication tag.
	AdditionalHeaders map[string]any

	// Unprotected holds the JWE Shared Unprotected Header, which is *not*
	// covered by the authentication tag. Only the JSON serializations can
	// carry it, so Encrypt rejects it.
	Unprotected map[string]any

	// AdditionalAuthenticatedData is authenticated but not encrypted, and is
	// carried in the "aad" member. Only the JSON serializations can carry
	// it, so Encrypt rejects it.
	AdditionalAuthenticatedData []byte

	// Compress selects raw DEFLATE compression of the plaintext and sets
	// "zip":"DEF". Compressing attacker-influenced plaintext alongside
	// secrets enables CRIME-style attacks; leave it off unless you know the
	// plaintext is safe to compress.
	Compress bool
}

// DecryptOptions configures JWE decryption. The zero value is what Decrypt
// uses.
type DecryptOptions struct {
	// Algorithms, when non-empty, restricts the accepted key management
	// "alg" values.
	Algorithms []string

	// Encryptions, when non-empty, restricts the accepted content
	// encryption "enc" values.
	Encryptions []string

	// KnownCritical lists extension header names the caller understands.
	// Any other name in "crit" causes rejection.
	KnownCritical []string

	// MaxDecompressed overrides MaxDecompressedSize for this call. Values
	// below or equal to zero select the default.
	MaxDecompressed int
}

// Encrypt encrypts plaintext and returns the JWE compact serialization
// "protected.encrypted_key.iv.ciphertext.tag".
//
// key is the recipient's key: an *rsa.PublicKey, an EC or X25519 public key, a
// []byte symmetric key (for "dir", the AES key wrapping algorithms, or a PBES2
// password), or a *JWK carrying one.
func Encrypt(plaintext []byte, key any, opts EncryptOptions) (string, error) {
	if len(opts.Unprotected) > 0 {
		return "", fmt.Errorf("%w: the compact serialization cannot carry unprotected headers", ErrInvalidHeader)
	}
	if len(opts.AdditionalAuthenticatedData) > 0 {
		return "", fmt.Errorf("%w: the compact serialization cannot carry 'aad'", ErrInvalidHeader)
	}
	resolved, err := resolveKey(key, opts.KeyID)
	if err != nil {
		return "", err
	}
	alg := opts.Algorithm
	if alg == "" {
		if jwk, ok := key.(*JWK); ok && jwk.Alg != "" && keyMgmts[jwk.Alg].name != "" {
			alg = jwk.Alg
		} else if alg, err = defaultKeyMgmtAlg(resolved); err != nil {
			return "", err
		}
	}
	km, err := lookupKeyMgmt(alg)
	if err != nil {
		return "", err
	}
	encName := opts.Encryption
	if encName == "" {
		encName = A256GCM
	}
	enc, err := lookupEnc(encName)
	if err != nil {
		return "", err
	}
	if err := checkJWKUsage(key, opts.KeyID, UseEnc, []string{alg, encName}, "encrypt", "wrapKey", "deriveKey"); err != nil {
		return "", err
	}

	header := copyHeader(opts.Header, opts.AdditionalHeaders)
	header["alg"] = alg
	header["enc"] = encName
	if opts.KeyID != "" {
		header["kid"] = opts.KeyID
	} else if jwk, ok := key.(*JWK); ok && jwk.Kid != "" {
		if _, present := header["kid"]; !present {
			header["kid"] = jwk.Kid
		}
	}
	if opts.Compress {
		header["zip"] = "DEF"
	}
	// The compact serialization has no unprotected header, so the protected
	// header is the whole merged view a recipient sees.
	if err := checkCriticalProduced(header); err != nil {
		return "", err
	}

	cek, encryptedKey, err := km.encryptKey(enc, resolved, header, nil)
	if err != nil {
		return "", err
	}

	body := plaintext
	if zip, _ := header["zip"].(string); zip != "" {
		if zip != "DEF" {
			return "", fmt.Errorf("%w: unsupported 'zip' %q", ErrInvalidHeader, zip)
		}
		if body, err = deflate(plaintext); err != nil {
			return "", err
		}
	}

	protectedB64, err := encodeHeader(header)
	if err != nil {
		return "", err
	}
	// The protected header, as ASCII octets, is the additional authenticated
	// data (RFC 7516 §5.1 step 14).
	iv, ciphertext, tag, err := enc.encrypt(cek, body, []byte(protectedB64))
	if err != nil {
		return "", err
	}
	return strings.Join([]string{
		protectedB64,
		EncodeSegment(encryptedKey),
		EncodeSegment(iv),
		EncodeSegment(ciphertext),
		EncodeSegment(tag),
	}, "."), nil
}

// Decrypt decrypts a JWE compact serialization and returns the plaintext and
// the protected header.
//
// Every cryptographic failure — a wrong key, a corrupt tag, invalid padding —
// reports the same ErrDecryptFailed, so nothing about the failure leaks back to
// the sender.
func Decrypt(token string, key any) (plaintext []byte, header map[string]any, err error) {
	return DecryptWithOptions(token, key, DecryptOptions{})
}

// DecryptWithOptions is Decrypt with explicit control over the accepted
// algorithms, the understood "crit" extensions, and the decompression bound.
func DecryptWithOptions(token string, key any, opts DecryptOptions) (plaintext []byte, header map[string]any, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 5 {
		return nil, nil, fmt.Errorf("%w: compact JWE must have 5 parts, got %d", ErrMalformed, len(parts))
	}
	protected, err := decodeHeader(parts[0])
	if err != nil {
		return nil, nil, err
	}
	if err := checkCritical(protected, opts.KnownCritical); err != nil {
		return nil, nil, err
	}

	seg := make([][]byte, 4)
	for i, name := range []string{"encrypted_key", "iv", "ciphertext", "tag"} {
		b, err := decodeOptionalSegment(name, parts[i+1])
		if err != nil {
			return nil, nil, err
		}
		seg[i] = b
	}

	// In the compact serialization the additional authenticated data is
	// exactly the encoded protected header.
	body, err := decryptOne(protected, seg[0], seg[1], seg[2], seg[3], []byte(parts[0]), key, opts)
	if err != nil {
		return nil, nil, err
	}
	return body, protected, nil
}

// deflate compresses b with raw DEFLATE, the format RFC 7516 §4.1.3 requires
// for "zip":"DEF".
func deflate(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(b); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// inflate decompresses raw DEFLATE data, refusing to produce more than limit
// octets. Reading one octet past the limit is what distinguishes a payload that
// merely fills the budget from a compression bomb.
func inflate(b []byte, limit int) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(b))
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("%w: invalid DEFLATE payload: %v", ErrMalformed, err)
	}
	if len(out) > limit {
		return nil, fmt.Errorf("%w: over %d octets", ErrCompressionLimit, limit)
	}
	return out, nil
}

// defaultKeyMgmtAlg picks the conventional key management algorithm for a key
// type, used when EncryptOptions.Algorithm is empty.
func defaultKeyMgmtAlg(key any) (string, error) {
	switch k := key.(type) {
	case *rsa.PublicKey, *rsa.PrivateKey:
		return RSA_OAEP_256, nil
	case *ecdsa.PublicKey, *ecdsa.PrivateKey, *ecdh.PublicKey, *ecdh.PrivateKey:
		return ECDH_ES, nil
	case []byte:
		switch len(k) {
		case 16:
			return A128KW, nil
		case 24:
			return A192KW, nil
		case 32:
			return A256KW, nil
		default:
			return "", fmt.Errorf("%w: cannot infer alg for a %d-octet symmetric key", ErrInvalidKey, len(k))
		}
	default:
		return "", fmt.Errorf("%w: cannot infer alg for key type %T", ErrInvalidKeyType, key)
	}
}
