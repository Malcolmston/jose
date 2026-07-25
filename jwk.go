package jose

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
)

// JWK is a JSON Web Key (RFC 7517). It holds the raw JWK parameters exactly as
// they appear in JSON; call Key to resolve the corresponding Go crypto key.
//
// The supported key types ("kty") are:
//
//	RSA  – *rsa.PublicKey / *rsa.PrivateKey
//	EC   – *ecdsa.PublicKey / *ecdsa.PrivateKey (curves P-256, P-384, P-521)
//	OKP  – ed25519.PublicKey / ed25519.PrivateKey (crv Ed25519),
//	       *ecdh.PublicKey / *ecdh.PrivateKey (crv X25519)
//	oct  – []byte (a symmetric secret)
//
// Every numeric parameter is unpadded base64url of a big-endian octet string,
// per RFC 7518.
type JWK struct {
	// Kty is the key type: "RSA", "EC", "OKP", or "oct".
	Kty string `json:"kty"`
	// Use is the intended public key use, "sig" or "enc" (optional).
	Use string `json:"use,omitempty"`
	// Alg is the algorithm intended for use with this key, e.g. "RS256".
	Alg string `json:"alg,omitempty"`
	// Kid is the key ID, matched against a JOSE "kid" header.
	Kid string `json:"kid,omitempty"`
	// Crv is the curve name for EC and OKP keys, e.g. "P-256" or "Ed25519".
	Crv string `json:"crv,omitempty"`

	// KeyOps lists the permitted key operations (optional).
	KeyOps []string `json:"key_ops,omitempty"`

	// N is the RSA modulus.
	N string `json:"n,omitempty"`
	// E is the RSA public exponent.
	E string `json:"e,omitempty"`
	// D is the RSA private exponent, or the EC/OKP private key.
	D string `json:"d,omitempty"`
	// P is the first RSA prime factor.
	P string `json:"p,omitempty"`
	// Q is the second RSA prime factor.
	Q string `json:"q,omitempty"`
	// DP is the RSA CRT exponent d mod (p-1).
	DP string `json:"dp,omitempty"`
	// DQ is the RSA CRT exponent d mod (q-1).
	DQ string `json:"dq,omitempty"`
	// QI is the RSA CRT coefficient q^-1 mod p.
	QI string `json:"qi,omitempty"`
	// X is the EC x coordinate, or the OKP public key.
	X string `json:"x,omitempty"`
	// Y is the EC y coordinate.
	Y string `json:"y,omitempty"`
	// K is the symmetric key material for kty "oct".
	K string `json:"k,omitempty"`
}

// JWKSet is a JWK Set (RFC 7517 §5), the "jwks" document commonly served at a
// provider's well-known endpoint.
type JWKSet struct {
	// Keys holds the set's keys in document order.
	Keys []*JWK `json:"keys"`
}

// ParseJWK decodes a single JWK from its JSON encoding. It validates the
// parameters by resolving the key, so a JWK that ParseJWK accepts is usable.
func ParseJWK(data []byte) (*JWK, error) {
	var k JWK
	if err := json.Unmarshal(data, &k); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	if _, err := k.Key(); err != nil {
		return nil, err
	}
	return &k, nil
}

// ParseJWKSet decodes a JWK Set document, validating every key it contains.
func ParseJWKSet(data []byte) (*JWKSet, error) {
	var s JWKSet
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	for i, k := range s.Keys {
		if k == nil {
			return nil, fmt.Errorf("%w: null key at index %d", ErrInvalidKey, i)
		}
		if _, err := k.Key(); err != nil {
			return nil, fmt.Errorf("key %d (kid %q): %w", i, k.Kid, err)
		}
	}
	return &s, nil
}

// LookupKeyID returns the first key in the set whose Kid equals kid. The second
// result reports whether such a key was found.
func (s *JWKSet) LookupKeyID(kid string) (*JWK, bool) {
	if s == nil {
		return nil, false
	}
	for _, k := range s.Keys {
		if k != nil && k.Kid == kid {
			return k, true
		}
	}
	return nil, false
}

// Key resolves the JWK into a Go crypto key. Private parameters, when present,
// produce a private key; otherwise the public key is returned. See the JWK
// documentation for the type each "kty" yields.
func (k *JWK) Key() (any, error) {
	switch k.Kty {
	case "RSA":
		return k.rsaKey()
	case "EC":
		return k.ecKey()
	case "OKP":
		return k.okpKey()
	case "oct":
		return k.octKey()
	case "":
		return nil, fmt.Errorf("%w: missing kty", ErrInvalidKey)
	default:
		return nil, fmt.Errorf("%w: unsupported kty %q", ErrInvalidKey, k.Kty)
	}
}

// Public returns a copy of the JWK holding only its public parameters. For a
// symmetric ("oct") key, which has no public form, Public reports an error.
func (k *JWK) Public() (*JWK, error) {
	if k.Kty == "oct" {
		return nil, fmt.Errorf("%w: symmetric key has no public part", ErrInvalidKey)
	}
	if _, err := k.Key(); err != nil {
		return nil, err
	}
	pub := *k
	pub.D, pub.P, pub.Q, pub.DP, pub.DQ, pub.QI, pub.K = "", "", "", "", "", "", ""
	return &pub, nil
}

// IsPrivate reports whether the JWK carries private key material.
func (k *JWK) IsPrivate() bool {
	switch k.Kty {
	case "RSA", "EC", "OKP":
		return k.D != ""
	case "oct":
		return k.K != ""
	default:
		return false
	}
}

// Thumbprint returns the RFC 7638 JWK thumbprint of the key: the unpadded
// base64url encoding of the SHA-256 digest of the canonical, minimal set of
// required members for the key type, serialized as lexicographically ordered
// compact JSON. It is stable across implementations and is the conventional
// way to derive a deterministic "kid".
func (k *JWK) Thumbprint() (string, error) {
	var canonical string
	switch k.Kty {
	case "RSA":
		if k.E == "" || k.N == "" {
			return "", fmt.Errorf("%w: rsa thumbprint needs n and e", ErrInvalidKey)
		}
		canonical = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, k.E, k.N)
	case "EC":
		if k.Crv == "" || k.X == "" || k.Y == "" {
			return "", fmt.Errorf("%w: ec thumbprint needs crv, x and y", ErrInvalidKey)
		}
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, k.Crv, k.X, k.Y)
	case "OKP":
		if k.Crv == "" || k.X == "" {
			return "", fmt.Errorf("%w: okp thumbprint needs crv and x", ErrInvalidKey)
		}
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"OKP","x":%q}`, k.Crv, k.X)
	case "oct":
		if k.K == "" {
			return "", fmt.Errorf("%w: oct thumbprint needs k", ErrInvalidKey)
		}
		canonical = fmt.Sprintf(`{"k":%q,"kty":"oct"}`, k.K)
	default:
		return "", fmt.Errorf("%w: cannot thumbprint kty %q", ErrInvalidKey, k.Kty)
	}
	sum := sha256.Sum256([]byte(canonical))
	return EncodeSegment(sum[:]), nil
}

// FromKey builds a JWK from a Go crypto key, populating the parameters that
// correspond to the key's type. It is the inverse of Key.
//
// The accepted types are *rsa.PublicKey, *rsa.PrivateKey, *ecdsa.PublicKey,
// *ecdsa.PrivateKey, ed25519.PublicKey, ed25519.PrivateKey, *ecdh.PublicKey and
// *ecdh.PrivateKey (X25519 only), and []byte for a symmetric key.
func FromKey(key any) (*JWK, error) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return jwkFromRSAPublic(k), nil
	case *rsa.PrivateKey:
		j := jwkFromRSAPublic(&k.PublicKey)
		j.D = EncodeSegment(k.D.Bytes())
		if len(k.Primes) >= 2 {
			j.P = EncodeSegment(k.Primes[0].Bytes())
			j.Q = EncodeSegment(k.Primes[1].Bytes())
		}
		if k.Precomputed.Dp != nil {
			j.DP = EncodeSegment(k.Precomputed.Dp.Bytes())
			j.DQ = EncodeSegment(k.Precomputed.Dq.Bytes())
			j.QI = EncodeSegment(k.Precomputed.Qinv.Bytes())
		}
		return j, nil
	case *ecdsa.PublicKey:
		return jwkFromECPublic(k)
	case *ecdsa.PrivateKey:
		j, err := jwkFromECPublic(&k.PublicKey)
		if err != nil {
			return nil, err
		}
		j.D = EncodeSegment(padBig(k.D, coordSize(k.Curve)))
		return j, nil
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: ed25519 public key has wrong length %d", ErrInvalidKey, len(k))
		}
		return &JWK{Kty: "OKP", Crv: "Ed25519", X: EncodeSegment(k)}, nil
	case ed25519.PrivateKey:
		if len(k) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("%w: ed25519 private key has wrong length %d", ErrInvalidKey, len(k))
		}
		pub, ok := k.Public().(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: invalid ed25519 private key", ErrInvalidKey)
		}
		return &JWK{Kty: "OKP", Crv: "Ed25519", X: EncodeSegment(pub), D: EncodeSegment(k.Seed())}, nil
	case *ecdh.PublicKey:
		return jwkFromECDHPublic(k)
	case *ecdh.PrivateKey:
		j, err := jwkFromECDHPublic(k.PublicKey())
		if err != nil {
			return nil, err
		}
		// crypto/ecdh already returns the fixed-width scalar for NIST curves
		// and the 32-octet scalar for X25519, which is what RFC 8037 and
		// RFC 7518 require for "d".
		j.D = EncodeSegment(k.Bytes())
		return j, nil
	case []byte:
		if len(k) == 0 {
			return nil, fmt.Errorf("%w: empty oct key", ErrInvalidKey)
		}
		return &JWK{Kty: "oct", K: EncodeSegment(k)}, nil
	case *JWK:
		return k, nil
	default:
		return nil, fmt.Errorf("%w: unsupported key type %T", ErrInvalidKey, key)
	}
}

// --- resolution helpers ---

// b64Field decodes a required base64url JWK parameter.
func b64Field(name, s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("%w: missing JWK field %q", ErrInvalidKey, name)
	}
	b, err := DecodeSegment(s)
	if err != nil {
		return nil, fmt.Errorf("%w: JWK field %q: %v", ErrInvalidKey, name, err)
	}
	return b, nil
}

// b64Int decodes a required base64url JWK parameter as a big-endian unsigned
// integer.
func b64Int(name, s string) (*big.Int, error) {
	b, err := b64Field(name, s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

func (k *JWK) rsaKey() (any, error) {
	n, err := b64Int("n", k.N)
	if err != nil {
		return nil, err
	}
	e, err := b64Int("e", k.E)
	if err != nil {
		return nil, err
	}
	if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
		return nil, fmt.Errorf("%w: rsa exponent out of range", ErrInvalidKey)
	}
	pub := &rsa.PublicKey{N: n, E: int(e.Int64())}
	if k.D == "" {
		return pub, nil
	}
	d, err := b64Int("d", k.D)
	if err != nil {
		return nil, err
	}
	priv := &rsa.PrivateKey{PublicKey: *pub, D: d}
	if k.P != "" && k.Q != "" {
		p, err := b64Int("p", k.P)
		if err != nil {
			return nil, err
		}
		q, err := b64Int("q", k.Q)
		if err != nil {
			return nil, err
		}
		priv.Primes = []*big.Int{p, q}
	}
	if err := priv.Validate(); err != nil {
		return nil, fmt.Errorf("%w: rsa key: %v", ErrInvalidKey, err)
	}
	priv.Precompute()
	return priv, nil
}

// ecCurve maps a JWK "crv" name to a standard elliptic curve.
func ecCurve(name string) (elliptic.Curve, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("%w: unsupported EC curve %q", ErrInvalidKey, name)
	}
}

// coordSize returns the octet length of one coordinate on curve.
func coordSize(c elliptic.Curve) int { return (c.Params().BitSize + 7) / 8 }

// padBig returns n as a big-endian octet string left-padded to size octets.
func padBig(n *big.Int, size int) []byte {
	b := make([]byte, size)
	n.FillBytes(b)
	return b
}

func (k *JWK) ecKey() (any, error) {
	curve, err := ecCurve(k.Crv)
	if err != nil {
		return nil, err
	}
	x, err := b64Int("x", k.X)
	if err != nil {
		return nil, err
	}
	y, err := b64Int("y", k.Y)
	if err != nil {
		return nil, err
	}
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("%w: EC point is not on curve %s", ErrInvalidKey, k.Crv)
	}
	pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	if k.D == "" {
		return pub, nil
	}
	d, err := b64Int("d", k.D)
	if err != nil {
		return nil, err
	}
	if d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 {
		return nil, fmt.Errorf("%w: EC private scalar out of range", ErrInvalidKey)
	}
	return &ecdsa.PrivateKey{PublicKey: *pub, D: d}, nil
}

func (k *JWK) okpKey() (any, error) {
	switch k.Crv {
	case "Ed25519":
		x, err := b64Field("x", k.X)
		if err != nil {
			return nil, err
		}
		if len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: ed25519 public key has wrong length %d", ErrInvalidKey, len(x))
		}
		if k.D == "" {
			return ed25519.PublicKey(x), nil
		}
		d, err := b64Field("d", k.D)
		if err != nil {
			return nil, err
		}
		if len(d) != ed25519.SeedSize {
			return nil, fmt.Errorf("%w: ed25519 seed has wrong length %d", ErrInvalidKey, len(d))
		}
		return ed25519.NewKeyFromSeed(d), nil
	case "X25519":
		x, err := b64Field("x", k.X)
		if err != nil {
			return nil, err
		}
		if k.D == "" {
			pub, err := ecdh.X25519().NewPublicKey(x)
			if err != nil {
				return nil, fmt.Errorf("%w: x25519 public key: %v", ErrInvalidKey, err)
			}
			return pub, nil
		}
		d, err := b64Field("d", k.D)
		if err != nil {
			return nil, err
		}
		priv, err := ecdh.X25519().NewPrivateKey(d)
		if err != nil {
			return nil, fmt.Errorf("%w: x25519 private key: %v", ErrInvalidKey, err)
		}
		return priv, nil
	default:
		return nil, fmt.Errorf("%w: unsupported OKP curve %q", ErrInvalidKey, k.Crv)
	}
}

func (k *JWK) octKey() (any, error) {
	b, err := b64Field("k", k.K)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func jwkFromRSAPublic(k *rsa.PublicKey) *JWK {
	return &JWK{
		Kty: "RSA",
		N:   EncodeSegment(k.N.Bytes()),
		E:   EncodeSegment(big.NewInt(int64(k.E)).Bytes()),
	}
}

func jwkFromECPublic(k *ecdsa.PublicKey) (*JWK, error) {
	if k.Curve == nil {
		return nil, fmt.Errorf("%w: EC key has no curve", ErrInvalidKey)
	}
	name := k.Curve.Params().Name
	if _, err := ecCurve(name); err != nil {
		return nil, err
	}
	size := coordSize(k.Curve)
	return &JWK{
		Kty: "EC",
		Crv: name,
		X:   EncodeSegment(padBig(k.X, size)),
		Y:   EncodeSegment(padBig(k.Y, size)),
	}, nil
}

func jwkFromECDHPublic(k *ecdh.PublicKey) (*JWK, error) {
	if k.Curve() == ecdh.X25519() {
		return &JWK{Kty: "OKP", Crv: "X25519", X: EncodeSegment(k.Bytes())}, nil
	}
	// NIST curves: convert to the ecdsa representation to reuse the encoding.
	ec, err := ecdhToECDSAPublic(k)
	if err != nil {
		return nil, err
	}
	return jwkFromECPublic(ec)
}
