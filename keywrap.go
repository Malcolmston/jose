package jose

import (
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

// aesKWIV is the default initial value A[0] defined by RFC 3394 §2.2.3.1.
var aesKWIV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// AESKeyWrap implements the AES Key Wrap algorithm of RFC 3394, the primitive
// behind the JWE "A128KW", "A192KW", and "A256KW" key management algorithms
// (and the key-wrapping half of "ECDH-ES+A128KW" and friends).
//
// kek is the key-encryption key (16, 24, or 32 octets) and plaintext is the key
// to wrap, whose length must be a multiple of 8 octets and at least 16. The
// result is 8 octets longer than the input.
//
// The Go standard library does not provide key wrap, so it is implemented here
// directly from the RFC's index-based pseudocode.
func AESKeyWrap(kek, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("%w: AES-KW: %v", ErrInvalidKey, err)
	}
	if len(plaintext)%8 != 0 || len(plaintext) < 16 {
		return nil, fmt.Errorf("%w: AES-KW input must be a multiple of 8 octets and at least 16", ErrInvalidKey)
	}
	n := len(plaintext) / 8

	a := make([]byte, 8)
	copy(a, aesKWIV)
	r := make([]byte, len(plaintext))
	copy(r, plaintext)

	buf := make([]byte, 16)
	for j := 0; j < 6; j++ {
		for i := 1; i <= n; i++ {
			copy(buf[:8], a)
			copy(buf[8:], r[(i-1)*8:i*8])
			block.Encrypt(buf, buf)
			// A = MSB(64, B) ^ t, where t = (n*j)+i
			t := uint64(n*j + i)
			copy(a, buf[:8])
			xorUint64(a, t)
			copy(r[(i-1)*8:i*8], buf[8:])
		}
	}
	out := make([]byte, 8+len(r))
	copy(out[:8], a)
	copy(out[8:], r)
	return out, nil
}

// AESKeyUnwrap reverses AESKeyWrap. The integrity check on the RFC 3394 initial
// value is performed in constant time; a failure yields ErrDecryptFailed and
// says nothing further about the cause.
func AESKeyUnwrap(kek, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("%w: AES-KW: %v", ErrInvalidKey, err)
	}
	if len(ciphertext)%8 != 0 || len(ciphertext) < 24 {
		return nil, fmt.Errorf("%w: AES-KW ciphertext must be a multiple of 8 octets and at least 24", ErrMalformed)
	}
	n := len(ciphertext)/8 - 1

	a := make([]byte, 8)
	copy(a, ciphertext[:8])
	r := make([]byte, len(ciphertext)-8)
	copy(r, ciphertext[8:])

	buf := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64(n*j + i)
			copy(buf[:8], a)
			xorUint64(buf[:8], t)
			copy(buf[8:], r[(i-1)*8:i*8])
			block.Decrypt(buf, buf)
			copy(a, buf[:8])
			copy(r[(i-1)*8:i*8], buf[8:])
		}
	}
	if subtle.ConstantTimeCompare(a, aesKWIV) != 1 {
		return nil, ErrDecryptFailed
	}
	return r, nil
}

// xorUint64 XORs t, encoded big-endian, into the last 8 octets of b.
func xorUint64(b []byte, t uint64) {
	var tb [8]byte
	binary.BigEndian.PutUint64(tb[:], t)
	for i := range tb {
		b[len(b)-8+i] ^= tb[i]
	}
}
