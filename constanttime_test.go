package jose

import (
	"crypto/hmac"
	"crypto/subtle"
	"errors"
	"strings"
	"testing"
)

// TestConstantTimeComparisonsCannotDegenerate pins the one property that makes
// a constant-time comparison safe to use as an authenticator check: it must
// never be reached with two empty operands.
//
// Both subtle.ConstantTimeCompare and hmac.Equal report *equal* for two
// zero-length slices — correctly, since they are equal — and that is exactly
// how an authentication bypass gets built. If any code path lets an attacker
// supply an empty tag and compares it against a value that is also empty
// (because a length check was skipped, or a "compute the expected tag" step
// short-circuited), the comparison returns true and the message is accepted
// with no authentication at all.
//
// This package has three such comparisons — the RFC 3394 integrity check in
// AESKeyUnwrap, the HMAC signature check in sigAlg.verify, and the CBC-HMAC tag
// check in contentEnc.decryptCBCHMAC. In each the expected value is a hash or
// MAC output of fixed, non-zero length, and each is guarded by an explicit
// length check upstream. The first assertion below states the hazard so it
// cannot be mistaken for a hypothetical; the rest walk the attacker's side of
// every one of those comparisons with an all-empty forgery.
func TestConstantTimeComparisonsCannotDegenerate(t *testing.T) {
	requireKeys(t)

	// The hazard itself. This is stdlib behaviour, not a bug — it is the
	// reason the guards below have to exist.
	if subtle.ConstantTimeCompare(nil, nil) != 1 {
		t.Fatal("subtle.ConstantTimeCompare(nil, nil) != 1; the premise of this test has changed")
	}
	if !hmac.Equal(nil, nil) {
		t.Fatal("hmac.Equal(nil, nil) == false; the premise of this test has changed")
	}

	t.Run("JWS HMAC signature", func(t *testing.T) {
		// An empty signature segment, and a signature that decodes to zero
		// octets, must both be refused before any comparison happens.
		protected, err := encodeHeader(map[string]any{"alg": HS256})
		if err != nil {
			t.Fatal(err)
		}
		token := protected + "." + EncodeSegment([]byte("x")) + "."
		if _, _, err := Verify(token, testKeys.oct32); err == nil {
			t.Error("Verify accepted a JWS with an empty signature")
		}
		// And an empty HMAC secret is refused too: HMAC keyed with nothing is
		// a public function, so the tag would not authenticate anybody.
		good, err := Sign([]byte("x"), testKeys.oct32, SignOptions{Algorithm: HS256})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := Verify(good, []byte{}); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("Verify with an empty secret: err = %v, want ErrInvalidKey", err)
		}
	})

	t.Run("AES key unwrap integrity check", func(t *testing.T) {
		kek := testKeys.oct16
		if _, err := AESKeyUnwrap(kek, nil); err == nil {
			t.Error("AESKeyUnwrap accepted an empty ciphertext")
		}
		// 16 octets is one block short of the 24-octet minimum: the loop would
		// run with n = 1 and leave A untouched if the bound were missing.
		if _, err := AESKeyUnwrap(kek, make([]byte, 16)); !errors.Is(err, ErrMalformed) {
			t.Errorf("AESKeyUnwrap(16 octets): err = %v, want ErrMalformed", err)
		}
	})

	t.Run("AES-GCM key wrap tag", func(t *testing.T) {
		if _, err := aesGCMUnwrap(testKeys.oct16, nil, nil, nil); !errors.Is(err, ErrDecryptFailed) {
			t.Errorf("aesGCMUnwrap with everything empty: err = %v, want ErrDecryptFailed", err)
		}
	})

	t.Run("content encryption tag", func(t *testing.T) {
		// Hand every content encryption algorithm a fully empty message: no
		// IV, no ciphertext, no tag. Each must fail, and each must fail with
		// the same undifferentiated error.
		for _, encName := range ContentEncryptionAlgorithms() {
			size, err := ContentEncryptionKeySize(encName)
			if err != nil {
				t.Fatal(err)
			}
			cek := randBytes(size)
			ce, err := lookupEnc(encName)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ce.decrypt(cek, nil, nil, nil, nil); !errors.Is(err, ErrDecryptFailed) {
				t.Errorf("%s: empty message: err = %v, want ErrDecryptFailed", encName, err)
			}

			// The same thing through the public API, as a compact JWE whose
			// last three segments are empty.
			protected, err := encodeHeader(map[string]any{"alg": Dir, "enc": encName})
			if err != nil {
				t.Fatal(err)
			}
			token := strings.Join([]string{protected, "", "", "", ""}, ".")
			if _, _, err := Decrypt(token, cek); !errors.Is(err, ErrDecryptFailed) {
				t.Errorf("%s: empty compact JWE: err = %v, want ErrDecryptFailed", encName, err)
			}
		}
	})
}
