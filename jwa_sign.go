package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256" // link SHA-256 for crypto.Hash.New
	_ "crypto/sha512" // link SHA-384 and SHA-512
	"fmt"
	"math/big"
	"sort"
)

// JWS signature algorithm identifiers ("alg"), RFC 7518 §3.
const (
	// HS256 is HMAC using SHA-256; the key is a []byte secret.
	HS256 = "HS256"
	// HS384 is HMAC using SHA-384; the key is a []byte secret.
	HS384 = "HS384"
	// HS512 is HMAC using SHA-512; the key is a []byte secret.
	HS512 = "HS512"
	// RS256 is RSASSA-PKCS1-v1_5 using SHA-256.
	RS256 = "RS256"
	// RS384 is RSASSA-PKCS1-v1_5 using SHA-384.
	RS384 = "RS384"
	// RS512 is RSASSA-PKCS1-v1_5 using SHA-512.
	RS512 = "RS512"
	// PS256 is RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
	PS256 = "PS256"
	// PS384 is RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
	PS384 = "PS384"
	// PS512 is RSASSA-PSS using SHA-512 and MGF1 with SHA-512.
	PS512 = "PS512"
	// ES256 is ECDSA using P-256 and SHA-256.
	ES256 = "ES256"
	// ES384 is ECDSA using P-384 and SHA-384.
	ES384 = "ES384"
	// ES512 is ECDSA using P-521 and SHA-512.
	ES512 = "ES512"
	// EdDSA is Edwards-curve DSA using Ed25519.
	EdDSA = "EdDSA"
	// None is the unsecured "none" algorithm. This package never verifies a
	// JWS that uses it; the constant exists so callers can detect it.
	None = "none"
)

// sigAlg describes one JWS signature algorithm.
type sigAlg struct {
	name  string
	hash  crypto.Hash
	kind  string // "hmac", "pkcs1", "pss", "ecdsa", "eddsa"
	crv   string // ECDSA only: required curve
	coord int    // ECDSA only: octets per r/s coordinate
}

var sigAlgs = map[string]sigAlg{
	HS256: {name: HS256, hash: crypto.SHA256, kind: "hmac"},
	HS384: {name: HS384, hash: crypto.SHA384, kind: "hmac"},
	HS512: {name: HS512, hash: crypto.SHA512, kind: "hmac"},
	RS256: {name: RS256, hash: crypto.SHA256, kind: "pkcs1"},
	RS384: {name: RS384, hash: crypto.SHA384, kind: "pkcs1"},
	RS512: {name: RS512, hash: crypto.SHA512, kind: "pkcs1"},
	PS256: {name: PS256, hash: crypto.SHA256, kind: "pss"},
	PS384: {name: PS384, hash: crypto.SHA384, kind: "pss"},
	PS512: {name: PS512, hash: crypto.SHA512, kind: "pss"},
	ES256: {name: ES256, hash: crypto.SHA256, kind: "ecdsa", crv: "P-256", coord: 32},
	ES384: {name: ES384, hash: crypto.SHA384, kind: "ecdsa", crv: "P-384", coord: 48},
	ES512: {name: ES512, hash: crypto.SHA512, kind: "ecdsa", crv: "P-521", coord: 66},
	EdDSA: {name: EdDSA, kind: "eddsa"},
}

// SignatureAlgorithms returns the sorted list of JWS "alg" values this package
// can sign and verify. The unsecured "none" algorithm is not included.
func SignatureAlgorithms() []string {
	out := make([]string, 0, len(sigAlgs))
	for k := range sigAlgs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// lookupSigAlg resolves a JWS "alg" identifier, refusing "none" outright.
func lookupSigAlg(alg string) (sigAlg, error) {
	if alg == None {
		return sigAlg{}, ErrNoneAlgDisallowed
	}
	a, ok := sigAlgs[alg]
	if !ok {
		return sigAlg{}, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, alg)
	}
	if a.hash != 0 && !a.hash.Available() {
		return sigAlg{}, fmt.Errorf("%w: hash for %q is not linked in", ErrUnsupportedAlgorithm, alg)
	}
	return a, nil
}

// digest hashes the signing input for algorithms that pre-hash.
func (a sigAlg) digest(input []byte) []byte {
	h := a.hash.New()
	h.Write(input)
	return h.Sum(nil)
}

// sign produces the raw JWS signature octets over input.
func (a sigAlg) sign(input []byte, key any) ([]byte, error) {
	switch a.kind {
	case "hmac":
		secret, ok := key.([]byte)
		if !ok {
			return nil, fmt.Errorf("%w: %s requires []byte, got %T", ErrInvalidKeyType, a.name, key)
		}
		if len(secret) == 0 {
			return nil, fmt.Errorf("%w: %s secret is empty", ErrInvalidKey, a.name)
		}
		mac := hmac.New(a.hash.New, secret)
		mac.Write(input)
		return mac.Sum(nil), nil

	case "pkcs1":
		priv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: %s requires *rsa.PrivateKey, got %T", ErrInvalidKeyType, a.name, key)
		}
		return rsa.SignPKCS1v15(rand.Reader, priv, a.hash, a.digest(input))

	case "pss":
		priv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: %s requires *rsa.PrivateKey, got %T", ErrInvalidKeyType, a.name, key)
		}
		// RFC 7518 §3.5 fixes the salt length at the hash output length.
		return rsa.SignPSS(rand.Reader, priv, a.hash, a.digest(input),
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: a.hash})

	case "ecdsa":
		priv, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: %s requires *ecdsa.PrivateKey, got %T", ErrInvalidKeyType, a.name, key)
		}
		if priv.Curve == nil || priv.Curve.Params().Name != a.crv {
			return nil, fmt.Errorf("%w: %s requires curve %s", ErrInvalidKeyType, a.name, a.crv)
		}
		r, s, err := ecdsa.Sign(rand.Reader, priv, a.digest(input))
		if err != nil {
			return nil, err
		}
		// RFC 7518 §3.4 mandates fixed-width r||s, not ASN.1 DER.
		sig := make([]byte, 2*a.coord)
		r.FillBytes(sig[:a.coord])
		s.FillBytes(sig[a.coord:])
		return sig, nil

	case "eddsa":
		priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: EdDSA requires ed25519.PrivateKey, got %T", ErrInvalidKeyType, key)
		}
		if len(priv) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("%w: ed25519 private key has wrong length", ErrInvalidKey)
		}
		return ed25519.Sign(priv, input), nil
	}
	return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, a.name)
}

// verify checks sig against input. It returns nil on success and an error
// wrapping ErrSignatureInvalid or ErrInvalidKeyType otherwise.
func (a sigAlg) verify(input, sig []byte, key any) error {
	switch a.kind {
	case "hmac":
		secret, ok := key.([]byte)
		if !ok {
			return fmt.Errorf("%w: %s requires []byte, got %T", ErrInvalidKeyType, a.name, key)
		}
		mac := hmac.New(a.hash.New, secret)
		mac.Write(input)
		if !hmac.Equal(sig, mac.Sum(nil)) {
			return ErrSignatureInvalid
		}
		return nil

	case "pkcs1":
		pub, err := rsaPublic(a.name, key)
		if err != nil {
			return err
		}
		if err := rsa.VerifyPKCS1v15(pub, a.hash, a.digest(input), sig); err != nil {
			return ErrSignatureInvalid
		}
		return nil

	case "pss":
		pub, err := rsaPublic(a.name, key)
		if err != nil {
			return err
		}
		if err := rsa.VerifyPSS(pub, a.hash, a.digest(input), sig,
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: a.hash}); err != nil {
			return ErrSignatureInvalid
		}
		return nil

	case "ecdsa":
		var pub *ecdsa.PublicKey
		switch k := key.(type) {
		case *ecdsa.PublicKey:
			pub = k
		case *ecdsa.PrivateKey:
			pub = &k.PublicKey
		default:
			return fmt.Errorf("%w: %s requires *ecdsa.PublicKey, got %T", ErrInvalidKeyType, a.name, key)
		}
		if pub.Curve == nil || pub.Curve.Params().Name != a.crv {
			return fmt.Errorf("%w: %s requires curve %s", ErrInvalidKeyType, a.name, a.crv)
		}
		if len(sig) != 2*a.coord {
			return fmt.Errorf("%w: expected a %d-octet signature, got %d", ErrSignatureInvalid, 2*a.coord, len(sig))
		}
		r := new(big.Int).SetBytes(sig[:a.coord])
		s := new(big.Int).SetBytes(sig[a.coord:])
		if !ecdsa.Verify(pub, a.digest(input), r, s) {
			return ErrSignatureInvalid
		}
		return nil

	case "eddsa":
		var pub ed25519.PublicKey
		switch k := key.(type) {
		case ed25519.PublicKey:
			pub = k
		case ed25519.PrivateKey:
			p, ok := k.Public().(ed25519.PublicKey)
			if !ok {
				return fmt.Errorf("%w: invalid ed25519 private key", ErrInvalidKey)
			}
			pub = p
		default:
			return fmt.Errorf("%w: EdDSA requires ed25519.PublicKey, got %T", ErrInvalidKeyType, key)
		}
		if len(pub) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: ed25519 public key has wrong length", ErrInvalidKey)
		}
		if !ed25519.Verify(pub, input, sig) {
			return ErrSignatureInvalid
		}
		return nil
	}
	return fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, a.name)
}

// rsaPublic extracts an *rsa.PublicKey from a public or private RSA key.
func rsaPublic(alg string, key any) (*rsa.PublicKey, error) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return k, nil
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	default:
		return nil, fmt.Errorf("%w: %s requires *rsa.PublicKey, got %T", ErrInvalidKeyType, alg, key)
	}
}

// defaultSigAlg picks the conventional signature algorithm for a key type,
// used when SignOptions.Algorithm is empty.
func defaultSigAlg(key any) (string, error) {
	switch k := key.(type) {
	case []byte:
		return HS256, nil
	case *rsa.PrivateKey, *rsa.PublicKey:
		return RS256, nil
	case ed25519.PrivateKey, ed25519.PublicKey:
		return EdDSA, nil
	case *ecdsa.PrivateKey:
		return ecdsaAlgFor(k.Curve.Params().Name)
	case *ecdsa.PublicKey:
		return ecdsaAlgFor(k.Curve.Params().Name)
	default:
		return "", fmt.Errorf("%w: cannot infer alg for key type %T", ErrInvalidKeyType, key)
	}
}

// ecdsaAlgFor maps an EC curve name to its RFC 7518 signature algorithm.
func ecdsaAlgFor(crv string) (string, error) {
	switch crv {
	case "P-256":
		return ES256, nil
	case "P-384":
		return ES384, nil
	case "P-521":
		return ES512, nil
	default:
		return "", fmt.Errorf("%w: no JWS alg for curve %q", ErrUnsupportedAlgorithm, crv)
	}
}
