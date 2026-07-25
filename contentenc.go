package jose

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"sort"
)

// Content encryption algorithm identifiers ("enc"), RFC 7518 §5.
const (
	// A128CBC_HS256 is AES-128 in CBC mode with HMAC-SHA-256 (truncated to
	// 128 bits); the CEK is 32 octets.
	A128CBC_HS256 = "A128CBC-HS256"
	// A192CBC_HS384 is AES-192 in CBC mode with HMAC-SHA-384 (truncated to
	// 192 bits); the CEK is 48 octets.
	A192CBC_HS384 = "A192CBC-HS384"
	// A256CBC_HS512 is AES-256 in CBC mode with HMAC-SHA-512 (truncated to
	// 256 bits); the CEK is 64 octets.
	A256CBC_HS512 = "A256CBC-HS512"
	// A128GCM is AES-128 in Galois/Counter Mode; the CEK is 16 octets.
	A128GCM = "A128GCM"
	// A192GCM is AES-192 in Galois/Counter Mode; the CEK is 24 octets.
	A192GCM = "A192GCM"
	// A256GCM is AES-256 in Galois/Counter Mode; the CEK is 32 octets.
	A256GCM = "A256GCM"
)

// contentEnc describes one content encryption algorithm.
type contentEnc struct {
	name    string
	keySize int // total CEK octets
	gcm     bool
	newHash func() hash.Hash // CBC-HMAC only
}

var contentEncs = map[string]contentEnc{
	A128CBC_HS256: {name: A128CBC_HS256, keySize: 32, newHash: sha256.New},
	A192CBC_HS384: {name: A192CBC_HS384, keySize: 48, newHash: sha512.New384},
	A256CBC_HS512: {name: A256CBC_HS512, keySize: 64, newHash: sha512.New},
	A128GCM:       {name: A128GCM, keySize: 16, gcm: true},
	A192GCM:       {name: A192GCM, keySize: 24, gcm: true},
	A256GCM:       {name: A256GCM, keySize: 32, gcm: true},
}

// ContentEncryptionAlgorithms returns the sorted list of "enc" values this
// package supports.
func ContentEncryptionAlgorithms() []string {
	out := make([]string, 0, len(contentEncs))
	for k := range contentEncs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ContentEncryptionKeySize returns the number of octets a content encryption
// key must have for the given "enc" algorithm.
func ContentEncryptionKeySize(enc string) (int, error) {
	ce, ok := contentEncs[enc]
	if !ok {
		return 0, fmt.Errorf("%w: %q", ErrUnsupportedEncryption, enc)
	}
	return ce.keySize, nil
}

// lookupEnc resolves an "enc" identifier.
func lookupEnc(enc string) (contentEnc, error) {
	ce, ok := contentEncs[enc]
	if !ok {
		return contentEnc{}, fmt.Errorf("%w: %q", ErrUnsupportedEncryption, enc)
	}
	return ce, nil
}

// encrypt performs authenticated encryption of plaintext with cek over the
// additional authenticated data aad, returning the IV, ciphertext, and tag.
func (ce contentEnc) encrypt(cek, plaintext, aad []byte) (iv, ciphertext, tag []byte, err error) {
	if len(cek) != ce.keySize {
		return nil, nil, nil, fmt.Errorf("%w: %s needs a %d-octet CEK, got %d", ErrInvalidKey, ce.name, ce.keySize, len(cek))
	}
	if ce.gcm {
		return ce.encryptGCM(cek, plaintext, aad)
	}
	return ce.encryptCBCHMAC(cek, plaintext, aad)
}

// decrypt reverses encrypt. Every failure returns ErrDecryptFailed with no
// further detail, so that padding, tag, and key errors are indistinguishable.
func (ce contentEnc) decrypt(cek, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	if len(cek) != ce.keySize {
		return nil, fmt.Errorf("%w: %s needs a %d-octet CEK, got %d", ErrInvalidKey, ce.name, ce.keySize, len(cek))
	}
	if ce.gcm {
		return ce.decryptGCM(cek, iv, ciphertext, tag, aad)
	}
	return ce.decryptCBCHMAC(cek, iv, ciphertext, tag, aad)
}

// --- AES-GCM (RFC 7518 §5.3) ---

func (ce contentEnc) newGCM(cek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	return cipher.NewGCM(block)
}

func (ce contentEnc) encryptGCM(cek, plaintext, aad []byte) (iv, ciphertext, tag []byte, err error) {
	aead, err := ce.newGCM(cek)
	if err != nil {
		return nil, nil, nil, err
	}
	iv = make([]byte, aead.NonceSize()) // 96 bits, as RFC 7518 requires
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, nil, err
	}
	sealed := aead.Seal(nil, iv, plaintext, aad)
	n := len(sealed) - aead.Overhead()
	return iv, sealed[:n], sealed[n:], nil
}

func (ce contentEnc) decryptGCM(cek, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	aead, err := ce.newGCM(cek)
	if err != nil {
		return nil, err
	}
	if len(iv) != aead.NonceSize() || len(tag) != aead.Overhead() {
		return nil, ErrDecryptFailed
	}
	sealed := make([]byte, 0, len(ciphertext)+len(tag))
	sealed = append(sealed, ciphertext...)
	sealed = append(sealed, tag...)
	out, err := aead.Open(nil, iv, sealed, aad)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return out, nil
}

// --- AES-CBC-HMAC-SHA2 (RFC 7518 §5.2) ---

// cbcSplit splits a CBC-HMAC CEK into its MAC key (the first half) and its
// encryption key (the second half), the order RFC 7518 §5.2.2.1 specifies.
func cbcSplit(cek []byte) (macKey, encKey []byte) {
	h := len(cek) / 2
	return cek[:h], cek[h:]
}

// cbcAL returns the AAD length field: the bit length of aad as a 64-bit
// big-endian integer. Note that it counts *bits*, not octets — a detail that
// trips up many implementations.
func cbcAL(aad []byte) []byte {
	var al [8]byte
	binary.BigEndian.PutUint64(al[:], uint64(len(aad))*8)
	return al[:]
}

// cbcTag computes the truncated authentication tag over AAD || IV || E || AL.
func (ce contentEnc) cbcTag(macKey, iv, ciphertext, aad []byte) []byte {
	mac := hmac.New(ce.newHash, macKey)
	mac.Write(aad)
	mac.Write(iv)
	mac.Write(ciphertext)
	mac.Write(cbcAL(aad))
	return mac.Sum(nil)[:len(macKey)]
}

func (ce contentEnc) encryptCBCHMAC(cek, plaintext, aad []byte) (iv, ciphertext, tag []byte, err error) {
	macKey, encKey := cbcSplit(cek)
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	iv = make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, nil, err
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext = make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	// Encrypt-then-MAC: the tag covers the ciphertext, never the plaintext.
	return iv, ciphertext, ce.cbcTag(macKey, iv, ciphertext, aad), nil
}

func (ce contentEnc) decryptCBCHMAC(cek, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	macKey, encKey := cbcSplit(cek)
	if len(iv) != aes.BlockSize || len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, ErrDecryptFailed
	}
	// Verify the tag in constant time *before* touching the ciphertext. This
	// is what keeps CBC decryption from behaving as a padding oracle.
	if !hmac.Equal(tag, ce.cbcTag(macKey, iv, ciphertext, aad)) {
		return nil, ErrDecryptFailed
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	padded := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(padded, ciphertext)
	out, ok := pkcs7Unpad(padded, aes.BlockSize)
	if !ok {
		return nil, ErrDecryptFailed
	}
	return out, nil
}

// pkcs7Pad appends PKCS#7 padding to b for the given block size, always adding
// at least one octet.
func pkcs7Pad(b []byte, blockSize int) []byte {
	n := blockSize - len(b)%blockSize
	out := make([]byte, len(b)+n)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(n)
	}
	return out
}

// pkcs7Unpad removes PKCS#7 padding. The check is uniform-time over the final
// block; regardless, the caller has already authenticated the ciphertext, so
// this result never reaches an attacker as a distinguishable error.
func pkcs7Unpad(b []byte, blockSize int) ([]byte, bool) {
	if len(b) == 0 || len(b)%blockSize != 0 {
		return nil, false
	}
	n := int(b[len(b)-1])
	if n == 0 || n > blockSize || n > len(b) {
		return nil, false
	}
	var bad byte
	for i := len(b) - n; i < len(b); i++ {
		bad |= b[i] ^ byte(n)
	}
	if bad != 0 {
		return nil, false
	}
	return b[:len(b)-n], true
}
