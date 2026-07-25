package jose

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
)

// ecdhCurveFor returns the crypto/ecdh curve matching a crypto/elliptic curve.
func ecdhCurveFor(c elliptic.Curve) (ecdh.Curve, error) {
	switch c {
	case elliptic.P256():
		return ecdh.P256(), nil
	case elliptic.P384():
		return ecdh.P384(), nil
	case elliptic.P521():
		return ecdh.P521(), nil
	default:
		return nil, fmt.Errorf("%w: curve %s does not support ECDH", ErrInvalidKey, c.Params().Name)
	}
}

// ellipticCurveFor returns the crypto/elliptic curve matching a crypto/ecdh
// curve, or nil for X25519, which has no elliptic.Curve representation.
func ellipticCurveFor(c ecdh.Curve) elliptic.Curve {
	switch c {
	case ecdh.P256():
		return elliptic.P256()
	case ecdh.P384():
		return elliptic.P384()
	case ecdh.P521():
		return elliptic.P521()
	default:
		return nil
	}
}

// ecdhToECDSAPublic converts a NIST-curve ECDH public key to its ecdsa form.
func ecdhToECDSAPublic(k *ecdh.PublicKey) (*ecdsa.PublicKey, error) {
	c := ellipticCurveFor(k.Curve())
	if c == nil {
		return nil, fmt.Errorf("%w: curve has no elliptic representation", ErrInvalidKey)
	}
	b := k.Bytes() // uncompressed point: 0x04 || X || Y
	size := coordSize(c)
	if len(b) != 1+2*size || b[0] != 4 {
		return nil, fmt.Errorf("%w: malformed EC point", ErrInvalidKey)
	}
	return &ecdsa.PublicKey{
		Curve: c,
		X:     new(big.Int).SetBytes(b[1 : 1+size]),
		Y:     new(big.Int).SetBytes(b[1+size:]),
	}, nil
}

// ecdsaToECDHPublic converts an ecdsa public key to its crypto/ecdh form.
func ecdsaToECDHPublic(k *ecdsa.PublicKey) (*ecdh.PublicKey, error) {
	c, err := ecdhCurveFor(k.Curve)
	if err != nil {
		return nil, err
	}
	size := coordSize(k.Curve)
	buf := make([]byte, 1+2*size)
	buf[0] = 4
	k.X.FillBytes(buf[1 : 1+size])
	k.Y.FillBytes(buf[1+size:])
	pub, err := c.NewPublicKey(buf)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	return pub, nil
}

// ecdsaToECDHPrivate converts an ecdsa private key to its crypto/ecdh form.
func ecdsaToECDHPrivate(k *ecdsa.PrivateKey) (*ecdh.PrivateKey, error) {
	c, err := ecdhCurveFor(k.Curve)
	if err != nil {
		return nil, err
	}
	priv, err := c.NewPrivateKey(padBig(k.D, coordSize(k.Curve)))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	return priv, nil
}

// asECDHPublic coerces a supported public key type into a crypto/ecdh key.
func asECDHPublic(key any) (*ecdh.PublicKey, error) {
	switch k := key.(type) {
	case *ecdh.PublicKey:
		return k, nil
	case *ecdh.PrivateKey:
		return k.PublicKey(), nil
	case *ecdsa.PublicKey:
		return ecdsaToECDHPublic(k)
	case *ecdsa.PrivateKey:
		return ecdsaToECDHPublic(&k.PublicKey)
	default:
		return nil, fmt.Errorf("%w: ECDH-ES requires an EC or X25519 key, got %T", ErrInvalidKeyType, key)
	}
}

// asECDHPrivate coerces a supported private key type into a crypto/ecdh key.
func asECDHPrivate(key any) (*ecdh.PrivateKey, error) {
	switch k := key.(type) {
	case *ecdh.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		return ecdsaToECDHPrivate(k)
	default:
		return nil, fmt.Errorf("%w: ECDH-ES requires an EC or X25519 private key, got %T", ErrInvalidKeyType, key)
	}
}

// ConcatKDF implements the NIST SP 800-56A Concatenation KDF in the single-hash
// form RFC 7518 §4.6.2 requires for ECDH-ES: SHA-256, no SuppPrivInfo, and an
// OtherInfo of
//
//	AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo
//
// where AlgorithmID, PartyUInfo, and PartyVInfo are each prefixed with their
// length as a 32-bit big-endian octet count, and SuppPubInfo is the derived key
// length in *bits* as a 32-bit big-endian integer.
//
// z is the raw ECDH shared secret, algID is the "enc" value for direct key
// agreement or the "alg" value when the agreed key wraps a CEK, apu and apv are
// the decoded "apu"/"apv" header parameters (either may be nil), and keyLen is
// the number of key octets to produce.
//
// Getting this encoding wrong is the classic JOSE interoperability bug; the
// RFC 7520 §5.4 and §5.5 vectors exercise both the wrapped and direct forms.
func ConcatKDF(z []byte, algID string, apu, apv []byte, keyLen int) ([]byte, error) {
	if keyLen <= 0 {
		return nil, fmt.Errorf("%w: concat KDF key length must be positive", ErrInvalidKey)
	}
	var other []byte
	other = append(other, lengthPrefixed([]byte(algID))...)
	other = append(other, lengthPrefixed(apu)...)
	other = append(other, lengthPrefixed(apv)...)
	var suppPub [4]byte
	binary.BigEndian.PutUint32(suppPub[:], uint32(keyLen)*8)
	other = append(other, suppPub[:]...)

	out := make([]byte, 0, keyLen)
	var counter [4]byte
	for i := uint32(1); len(out) < keyLen; i++ {
		binary.BigEndian.PutUint32(counter[:], i)
		h := sha256.New()
		h.Write(counter[:])
		h.Write(z)
		h.Write(other)
		out = h.Sum(out)
	}
	return out[:keyLen], nil
}

// lengthPrefixed returns b prefixed with its length as a 32-bit big-endian
// octet count, the "Datalen || Data" encoding SP 800-56A uses.
func lengthPrefixed(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out[:4], uint32(len(b)))
	copy(out[4:], b)
	return out
}

// ecdhDerive performs the ECDH key agreement and Concat KDF derivation for
// ECDH-ES. epk is the ephemeral key pair's private key when encrypting; when
// decrypting, priv is the recipient's static private key and pub is the
// sender's ephemeral public key.
func ecdhDerive(priv *ecdh.PrivateKey, pub *ecdh.PublicKey, algID string, apu, apv []byte, keyLen int) ([]byte, error) {
	if priv.Curve() != pub.Curve() {
		return nil, fmt.Errorf("%w: ECDH curve mismatch", ErrInvalidKey)
	}
	z, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: ECDH: %v", ErrInvalidKey, err)
	}
	return ConcatKDF(z, algID, apu, apv, keyLen)
}

// ecdhGenerate creates an ephemeral key pair on the same curve as pub.
func ecdhGenerate(pub *ecdh.PublicKey) (*ecdh.PrivateKey, error) {
	priv, err := pub.Curve().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%w: ephemeral key: %v", ErrInvalidKey, err)
	}
	return priv, nil
}
