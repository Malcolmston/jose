package jose

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"hash"
)

// PBKDF2 iteration bounds enforced by the PBES2 key management algorithms.
const (
	// DefaultPBES2Count is the PBKDF2 iteration count used when a caller does
	// not set "p2c" explicitly.
	DefaultPBES2Count = 100000

	// MinPBES2Count is the smallest iteration count this package will accept
	// when decrypting. RFC 7518 §4.8.1.2 recommends a minimum of 1000.
	MinPBES2Count = 1000

	// MaxPBES2Count is the largest iteration count this package will accept.
	// The "p2c" header is attacker-controlled, so an unbounded count is a
	// denial-of-service vector: a token asking for a billion iterations would
	// pin a CPU for minutes before any authentication happens.
	MaxPBES2Count = 1000000

	// MaxPBES2SaltInput is the largest "p2s" salt input accepted, again to
	// bound work driven by attacker-supplied headers.
	MaxPBES2SaltInput = 1024
)

// PBKDF2 derives a key of keyLen octets from password and salt using
// PBKDF2-HMAC (RFC 8018 §5.2) with the hash constructed by newHash and the
// given iteration count.
//
// The Go standard library does not ship PBKDF2 outside golang.org/x/crypto, so
// it is implemented here directly from the RFC.
func PBKDF2(password, salt []byte, iterations, keyLen int, newHash func() hash.Hash) ([]byte, error) {
	if iterations <= 0 {
		return nil, fmt.Errorf("%w: iteration count must be positive", ErrIterationCount)
	}
	if keyLen <= 0 {
		return nil, fmt.Errorf("%w: PBKDF2 key length must be positive", ErrInvalidKey)
	}
	prf := hmac.New(newHash, password)
	hLen := prf.Size()
	blocks := (keyLen + hLen - 1) / hLen

	out := make([]byte, 0, blocks*hLen)
	u := make([]byte, hLen)
	t := make([]byte, hLen)
	var idx [4]byte
	for b := 1; b <= blocks; b++ {
		binary.BigEndian.PutUint32(idx[:], uint32(b))
		prf.Reset()
		prf.Write(salt)
		prf.Write(idx[:])
		u = prf.Sum(u[:0])
		copy(t, u)
		for i := 1; i < iterations; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen], nil
}

// pbes2SaltInput builds the PBKDF2 salt required by RFC 7518 §4.8.1.1:
//
//	(UTF8(alg)) || 0x00 || Salt Input
//
// Binding the algorithm name into the salt keeps a derived key from being
// reused across PBES2 variants.
func pbes2SaltInput(alg string, p2s []byte) []byte {
	out := make([]byte, 0, len(alg)+1+len(p2s))
	out = append(out, alg...)
	out = append(out, 0x00)
	out = append(out, p2s...)
	return out
}
