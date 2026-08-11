package jose

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // RSA-OAEP with SHA-1 is required by the "RSA-OAEP" alg
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"hash"
	"math"
	"sort"
)

// JWE key management algorithm identifiers ("alg"), RFC 7518 §4.
const (
	// RSA1_5 is RSAES-PKCS1-v1_5. It is supported for interoperability with
	// existing deployments (and the RFC 7520 §5.1 vector) but is vulnerable
	// to Bleichenbacher-style attacks; prefer RSA-OAEP-256.
	RSA1_5 = "RSA1_5"
	// RSA_OAEP is RSAES-OAEP using SHA-1 and MGF1 with SHA-1.
	RSA_OAEP = "RSA-OAEP"
	// RSA_OAEP_256 is RSAES-OAEP using SHA-256 and MGF1 with SHA-256.
	RSA_OAEP_256 = "RSA-OAEP-256"
	// A128KW is AES Key Wrap (RFC 3394) with a 128-bit key.
	A128KW = "A128KW"
	// A192KW is AES Key Wrap (RFC 3394) with a 192-bit key.
	A192KW = "A192KW"
	// A256KW is AES Key Wrap (RFC 3394) with a 256-bit key.
	A256KW = "A256KW"
	// Dir uses the supplied symmetric key directly as the content
	// encryption key; no key is transmitted.
	Dir = "dir"
	// ECDH_ES is Elliptic Curve Diffie-Hellman Ephemeral Static key
	// agreement using Concat KDF; the agreed key is the CEK.
	ECDH_ES = "ECDH-ES"
	// ECDH_ES_A128KW agrees a 128-bit key with ECDH-ES and uses it to wrap
	// the CEK with AES Key Wrap.
	ECDH_ES_A128KW = "ECDH-ES+A128KW"
	// ECDH_ES_A192KW agrees a 192-bit key with ECDH-ES and uses it to wrap
	// the CEK with AES Key Wrap.
	ECDH_ES_A192KW = "ECDH-ES+A192KW"
	// ECDH_ES_A256KW agrees a 256-bit key with ECDH-ES and uses it to wrap
	// the CEK with AES Key Wrap.
	ECDH_ES_A256KW = "ECDH-ES+A256KW"
	// A128GCMKW wraps the CEK with AES-128 in GCM mode.
	A128GCMKW = "A128GCMKW"
	// A192GCMKW wraps the CEK with AES-192 in GCM mode.
	A192GCMKW = "A192GCMKW"
	// A256GCMKW wraps the CEK with AES-256 in GCM mode.
	A256GCMKW = "A256GCMKW"
	// PBES2_HS256_A128KW derives a key from a password with
	// PBKDF2-HMAC-SHA-256 and wraps the CEK with A128KW.
	PBES2_HS256_A128KW = "PBES2-HS256+A128KW"
	// PBES2_HS384_A192KW derives a key from a password with
	// PBKDF2-HMAC-SHA-384 and wraps the CEK with A192KW.
	PBES2_HS384_A192KW = "PBES2-HS384+A192KW"
	// PBES2_HS512_A256KW derives a key from a password with
	// PBKDF2-HMAC-SHA-512 and wraps the CEK with A256KW.
	PBES2_HS512_A256KW = "PBES2-HS512+A256KW"
)

// keyMgmt describes one JWE key management algorithm.
type keyMgmt struct {
	name string
	kind string // "rsa", "kw", "dir", "ecdh", "gcmkw", "pbes2"

	oaepHash func() hash.Hash // rsa: nil selects PKCS #1 v1.5
	wrapBits int              // kw/gcmkw/ecdh+kw/pbes2: AES key size in bits
	prf      func() hash.Hash // pbes2: PBKDF2 PRF
}

var keyMgmts = map[string]keyMgmt{
	RSA1_5:             {name: RSA1_5, kind: "rsa"},
	RSA_OAEP:           {name: RSA_OAEP, kind: "rsa", oaepHash: sha1.New},
	RSA_OAEP_256:       {name: RSA_OAEP_256, kind: "rsa", oaepHash: sha256.New},
	A128KW:             {name: A128KW, kind: "kw", wrapBits: 128},
	A192KW:             {name: A192KW, kind: "kw", wrapBits: 192},
	A256KW:             {name: A256KW, kind: "kw", wrapBits: 256},
	Dir:                {name: Dir, kind: "dir"},
	ECDH_ES:            {name: ECDH_ES, kind: "ecdh"},
	ECDH_ES_A128KW:     {name: ECDH_ES_A128KW, kind: "ecdh", wrapBits: 128},
	ECDH_ES_A192KW:     {name: ECDH_ES_A192KW, kind: "ecdh", wrapBits: 192},
	ECDH_ES_A256KW:     {name: ECDH_ES_A256KW, kind: "ecdh", wrapBits: 256},
	A128GCMKW:          {name: A128GCMKW, kind: "gcmkw", wrapBits: 128},
	A192GCMKW:          {name: A192GCMKW, kind: "gcmkw", wrapBits: 192},
	A256GCMKW:          {name: A256GCMKW, kind: "gcmkw", wrapBits: 256},
	PBES2_HS256_A128KW: {name: PBES2_HS256_A128KW, kind: "pbes2", wrapBits: 128, prf: sha256.New},
	PBES2_HS384_A192KW: {name: PBES2_HS384_A192KW, kind: "pbes2", wrapBits: 192, prf: sha512.New384},
	PBES2_HS512_A256KW: {name: PBES2_HS512_A256KW, kind: "pbes2", wrapBits: 256, prf: sha512.New},
}

// KeyManagementAlgorithms returns the sorted list of JWE "alg" values this
// package supports.
func KeyManagementAlgorithms() []string {
	out := make([]string, 0, len(keyMgmts))
	for k := range keyMgmts {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// lookupKeyMgmt resolves a JWE "alg" identifier.
func lookupKeyMgmt(alg string) (keyMgmt, error) {
	km, ok := keyMgmts[alg]
	if !ok {
		return keyMgmt{}, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, alg)
	}
	return km, nil
}

// wrapKeySize returns the AES key-wrapping key size in octets.
func (km keyMgmt) wrapKeySize() int { return km.wrapBits / 8 }

// newCEK generates a fresh random content encryption key of size octets.
func newCEK(size int) ([]byte, error) {
	cek := make([]byte, size)
	if _, err := rand.Read(cek); err != nil {
		return nil, err
	}
	return cek, nil
}

// derivesCEK reports whether the algorithm produces the content encryption key
// itself rather than transporting one. Such algorithms ("dir" and direct
// ECDH-ES) can address only a single recipient, since every recipient of a JWE
// shares one CEK.
func (km keyMgmt) derivesCEK() bool {
	return km.kind == "dir" || (km.kind == "ecdh" && km.wrapBits == 0)
}

// encryptKey produces the content encryption key and the JWE Encrypted Key for
// one recipient, adding any algorithm-specific parameters (epk, iv, tag, p2s,
// p2c) to header.
//
// When cek is non-nil it is the CEK to transport, which is how a
// multi-recipient JWE gives every recipient the same key; algorithms that
// derive the CEK reject it.
func (km keyMgmt) encryptKey(enc contentEnc, key any, header map[string]any, cek []byte) (_, encryptedKey []byte, err error) {
	if cek != nil && km.derivesCEK() {
		return nil, nil, fmt.Errorf("%w: %s derives the content encryption key and cannot address multiple recipients", ErrUnsupportedAlgorithm, km.name)
	}
	if cek == nil && !km.derivesCEK() {
		if cek, err = newCEK(enc.keySize); err != nil {
			return nil, nil, err
		}
	}
	switch km.kind {
	case "rsa":
		pub, err := rsaPublic(km.name, key)
		if err != nil {
			return nil, nil, err
		}
		if km.oaepHash == nil {
			encryptedKey, err = rsa.EncryptPKCS1v15(rand.Reader, pub, cek)
		} else {
			encryptedKey, err = rsa.EncryptOAEP(km.oaepHash(), rand.Reader, pub, cek, nil)
		}
		if err != nil {
			return nil, nil, err
		}
		return cek, encryptedKey, nil

	case "kw":
		kek, err := symmetricKey(km.name, key, km.wrapKeySize())
		if err != nil {
			return nil, nil, err
		}
		encryptedKey, err = AESKeyWrap(kek, cek)
		if err != nil {
			return nil, nil, err
		}
		return cek, encryptedKey, nil

	case "dir":
		derived, err := symmetricKey(km.name, key, enc.keySize)
		if err != nil {
			return nil, nil, err
		}
		return derived, nil, nil

	case "ecdh":
		return km.encryptKeyECDH(enc, key, header, cek)

	case "gcmkw":
		kek, err := symmetricKey(km.name, key, km.wrapKeySize())
		if err != nil {
			return nil, nil, err
		}
		iv, wrapped, tag, err := aesGCMWrap(kek, cek)
		if err != nil {
			return nil, nil, err
		}
		header["iv"] = EncodeSegment(iv)
		header["tag"] = EncodeSegment(tag)
		return cek, wrapped, nil

	case "pbes2":
		return km.encryptKeyPBES2(key, header, cek)
	}
	return nil, nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, km.name)
}

// decryptKey recovers the content encryption key from the JWE Encrypted Key.
func (km keyMgmt) decryptKey(enc contentEnc, key any, header map[string]any, encryptedKey []byte) ([]byte, error) {
	switch km.kind {
	case "rsa":
		priv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: %s requires *rsa.PrivateKey, got %T", ErrInvalidKeyType, km.name, key)
		}
		var (
			cek []byte
			err error
		)
		if km.oaepHash == nil {
			// A fixed-length session key defeats the Bleichenbacher
			// distinguisher: crypto/rsa returns random bytes rather than an
			// error when the padding is bad.
			cek = make([]byte, enc.keySize)
			err = rsa.DecryptPKCS1v15SessionKey(rand.Reader, priv, encryptedKey, cek)
		} else {
			cek, err = rsa.DecryptOAEP(km.oaepHash(), rand.Reader, priv, encryptedKey, nil)
		}
		if err != nil {
			return nil, ErrDecryptFailed
		}
		return cek, nil

	case "kw":
		kek, err := symmetricKey(km.name, key, km.wrapKeySize())
		if err != nil {
			return nil, err
		}
		return AESKeyUnwrap(kek, encryptedKey)

	case "dir":
		if len(encryptedKey) != 0 {
			return nil, fmt.Errorf("%w: 'dir' must have an empty encrypted key", ErrMalformed)
		}
		return symmetricKey(km.name, key, enc.keySize)

	case "ecdh":
		return km.decryptKeyECDH(enc, key, header, encryptedKey)

	case "gcmkw":
		kek, err := symmetricKey(km.name, key, km.wrapKeySize())
		if err != nil {
			return nil, err
		}
		iv, err := headerBytes(header, "iv")
		if err != nil {
			return nil, err
		}
		tag, err := headerBytes(header, "tag")
		if err != nil {
			return nil, err
		}
		return aesGCMUnwrap(kek, iv, encryptedKey, tag)

	case "pbes2":
		return km.decryptKeyPBES2(key, header, encryptedKey)
	}
	return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, km.name)
}

// --- ECDH-ES ---

// ecdhAlgID returns the AlgorithmID and derived key length Concat KDF must use:
// the "enc" value and the CEK length for direct agreement, or the "alg" value
// and the wrapping key length when the agreed key wraps a CEK (RFC 7518 §4.6.2).
func (km keyMgmt) ecdhAlgID(enc contentEnc) (string, int) {
	if km.wrapBits == 0 {
		return enc.name, enc.keySize
	}
	return km.name, km.wrapKeySize()
}

func (km keyMgmt) encryptKeyECDH(enc contentEnc, key any, header map[string]any, cek []byte) (_, encryptedKey []byte, err error) {
	pub, err := asECDHPublic(key)
	if err != nil {
		return nil, nil, err
	}
	eph, err := ecdhGenerate(pub)
	if err != nil {
		return nil, nil, err
	}
	epk, err := FromKey(eph.PublicKey())
	if err != nil {
		return nil, nil, err
	}
	epkMap, err := jwkToMap(epk)
	if err != nil {
		return nil, nil, err
	}
	header["epk"] = epkMap

	apu, err := headerBytesOptional(header, "apu")
	if err != nil {
		return nil, nil, err
	}
	apv, err := headerBytesOptional(header, "apv")
	if err != nil {
		return nil, nil, err
	}
	algID, keyLen := km.ecdhAlgID(enc)
	agreed, err := ecdhDerive(eph, pub, algID, apu, apv, keyLen)
	if err != nil {
		return nil, nil, err
	}
	if km.wrapBits == 0 {
		return agreed, nil, nil
	}
	encryptedKey, err = AESKeyWrap(agreed, cek)
	if err != nil {
		return nil, nil, err
	}
	return cek, encryptedKey, nil
}

func (km keyMgmt) decryptKeyECDH(enc contentEnc, key any, header map[string]any, encryptedKey []byte) ([]byte, error) {
	priv, err := asECDHPrivate(key)
	if err != nil {
		return nil, err
	}
	raw, ok := header["epk"]
	if !ok {
		return nil, fmt.Errorf("%w: ECDH-ES requires an 'epk' header", ErrInvalidHeader)
	}
	epkJSON, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: bad 'epk' header: %v", ErrInvalidHeader, err)
	}
	epk, err := ParseJWK(epkJSON)
	if err != nil {
		return nil, err
	}
	if epk.IsPrivate() {
		return nil, fmt.Errorf("%w: 'epk' must not contain private parameters", ErrInvalidHeader)
	}
	epkKey, err := epk.Key()
	if err != nil {
		return nil, err
	}
	var pub *ecdh.PublicKey
	switch k := epkKey.(type) {
	case *ecdh.PublicKey:
		pub = k
	case *ecdsa.PublicKey:
		if pub, err = ecdsaToECDHPublic(k); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: 'epk' is not an ECDH key", ErrInvalidHeader)
	}

	apu, err := headerBytesOptional(header, "apu")
	if err != nil {
		return nil, err
	}
	apv, err := headerBytesOptional(header, "apv")
	if err != nil {
		return nil, err
	}
	algID, keyLen := km.ecdhAlgID(enc)
	agreed, err := ecdhDerive(priv, pub, algID, apu, apv, keyLen)
	if err != nil {
		return nil, err
	}
	if km.wrapBits == 0 {
		if len(encryptedKey) != 0 {
			return nil, fmt.Errorf("%w: ECDH-ES must have an empty encrypted key", ErrMalformed)
		}
		return agreed, nil
	}
	return AESKeyUnwrap(agreed, encryptedKey)
}

// --- PBES2 ---

func (km keyMgmt) encryptKeyPBES2(key any, header map[string]any, cek []byte) (_, encryptedKey []byte, err error) {
	password, err := passwordKey(km.name, key)
	if err != nil {
		return nil, nil, err
	}
	count := DefaultPBES2Count
	if raw, ok := header["p2c"]; ok {
		count, err = headerInt(raw)
		if err != nil {
			return nil, nil, err
		}
	}
	if count < MinPBES2Count || count > MaxPBES2Count {
		return nil, nil, fmt.Errorf("%w: p2c=%d is outside [%d,%d]", ErrIterationCount, count, MinPBES2Count, MaxPBES2Count)
	}
	var salt []byte
	if _, ok := header["p2s"]; ok {
		if salt, err = headerBytes(header, "p2s"); err != nil {
			return nil, nil, err
		}
	} else {
		salt = make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}
	// The same bounds decryptKeyPBES2 enforces. RFC 7518 §4.8.1.1 sets the
	// 8-octet floor; MaxPBES2SaltInput is this package's ceiling, and a caller
	// who supplies a larger "p2s" must be told here rather than handed a token
	// that no recipient — including this package — will ever unwrap.
	if len(salt) < 8 || len(salt) > MaxPBES2SaltInput {
		return nil, nil, fmt.Errorf("%w: 'p2s' length %d is out of range [8,%d]", ErrInvalidHeader, len(salt), MaxPBES2SaltInput)
	}
	header["p2s"] = EncodeSegment(salt)
	header["p2c"] = count

	kek, err := PBKDF2(password, pbes2SaltInput(km.name, salt), count, km.wrapKeySize(), km.prf)
	if err != nil {
		return nil, nil, err
	}
	encryptedKey, err = AESKeyWrap(kek, cek)
	if err != nil {
		return nil, nil, err
	}
	return cek, encryptedKey, nil
}

func (km keyMgmt) decryptKeyPBES2(key any, header map[string]any, encryptedKey []byte) ([]byte, error) {
	password, err := passwordKey(km.name, key)
	if err != nil {
		return nil, err
	}
	raw, ok := header["p2c"]
	if !ok {
		return nil, fmt.Errorf("%w: PBES2 requires a 'p2c' header", ErrInvalidHeader)
	}
	count, err := headerInt(raw)
	if err != nil {
		return nil, err
	}
	// Bound the work before doing any: "p2c" is attacker-supplied.
	if count < MinPBES2Count || count > MaxPBES2Count {
		return nil, fmt.Errorf("%w: p2c=%d is outside [%d,%d]", ErrIterationCount, count, MinPBES2Count, MaxPBES2Count)
	}
	salt, err := headerBytes(header, "p2s")
	if err != nil {
		return nil, err
	}
	if len(salt) < 8 || len(salt) > MaxPBES2SaltInput {
		return nil, fmt.Errorf("%w: 'p2s' length %d is out of range", ErrInvalidHeader, len(salt))
	}
	kek, err := PBKDF2(password, pbes2SaltInput(km.name, salt), count, km.wrapKeySize(), km.prf)
	if err != nil {
		return nil, err
	}
	return AESKeyUnwrap(kek, encryptedKey)
}

// --- AES-GCM key wrapping ---

// aesGCMWrap encrypts cek under kek with AES-GCM, returning the 96-bit IV, the
// wrapped key, and the 128-bit tag that the "iv" and "tag" headers carry.
func aesGCMWrap(kek, cek []byte) (iv, wrapped, tag []byte, err error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}
	iv = make([]byte, aead.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, nil, err
	}
	sealed := aead.Seal(nil, iv, cek, nil)
	n := len(sealed) - aead.Overhead()
	return iv, sealed[:n], sealed[n:], nil
}

// aesGCMUnwrap reverses aesGCMWrap.
func aesGCMUnwrap(kek, iv, wrapped, tag []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(iv) != aead.NonceSize() || len(tag) != aead.Overhead() {
		return nil, ErrDecryptFailed
	}
	sealed := make([]byte, 0, len(wrapped)+len(tag))
	sealed = append(sealed, wrapped...)
	sealed = append(sealed, tag...)
	out, err := aead.Open(nil, iv, sealed, nil)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return out, nil
}

// --- key coercion helpers ---

// symmetricKey type-asserts a symmetric key and checks its length.
func symmetricKey(alg string, key any, size int) ([]byte, error) {
	b, ok := key.([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: %s requires []byte, got %T", ErrInvalidKeyType, alg, key)
	}
	if len(b) != size {
		return nil, fmt.Errorf("%w: %s requires a %d-octet key, got %d", ErrInvalidKey, alg, size, len(b))
	}
	return b, nil
}

// passwordKey accepts a PBES2 password as either []byte or string.
func passwordKey(alg string, key any) ([]byte, error) {
	switch k := key.(type) {
	case []byte:
		if len(k) == 0 {
			return nil, fmt.Errorf("%w: %s password is empty", ErrInvalidKey, alg)
		}
		return k, nil
	case string:
		if k == "" {
			return nil, fmt.Errorf("%w: %s password is empty", ErrInvalidKey, alg)
		}
		return []byte(k), nil
	default:
		return nil, fmt.Errorf("%w: %s requires a []byte or string password, got %T", ErrInvalidKeyType, alg, key)
	}
}

// headerBytes decodes a required base64url header parameter.
func headerBytes(header map[string]any, name string) ([]byte, error) {
	raw, ok := header[name]
	if !ok {
		return nil, fmt.Errorf("%w: missing %q header", ErrInvalidHeader, name)
	}
	s, ok := raw.(string)
	if !ok {
		return nil, fmt.Errorf("%w: %q must be a string", ErrInvalidHeader, name)
	}
	b, err := DecodeSegment(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %q is not base64url: %v", ErrInvalidHeader, name, err)
	}
	return b, nil
}

// headerBytesOptional decodes an optional base64url header parameter, returning
// nil when it is absent.
func headerBytesOptional(header map[string]any, name string) ([]byte, error) {
	if _, ok := header[name]; !ok {
		return nil, nil
	}
	return headerBytes(header, name)
}

// headerInt reads a header parameter as an integer, accepting the float64 that
// encoding/json produces as well as the int a caller may set directly.
func headerInt(raw any) (int, error) {
	switch v := raw.(type) {
	case float64:
		// Range-check before converting: Go leaves a float-to-int conversion
		// implementation-defined when the value does not fit, so an
		// attacker-supplied 1e300 must never reach int().
		if v < math.MinInt32 || v > math.MaxInt32 || v != math.Trunc(v) {
			return 0, fmt.Errorf("%w: expected an integer header value", ErrInvalidHeader)
		}
		return int(v), nil
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return 0, fmt.Errorf("%w: %v", ErrInvalidHeader, err)
		}
		return int(n), nil
	default:
		return 0, fmt.Errorf("%w: expected an integer header value, got %T", ErrInvalidHeader, raw)
	}
}

// jwkToMap renders a JWK as a generic JSON object, the form a header parameter
// such as "epk" takes.
func jwkToMap(k *JWK) (map[string]any, error) {
	raw, err := json.Marshal(k)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	return m, nil
}
