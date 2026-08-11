package jose

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// This file holds the producer-side counterparts of the checks the verifier and
// the decrypter make. The invariant under test is one sentence long: *this
// package must never emit a document it would itself refuse to read.*
//
// A one-sided check is worse than no check. The recipient still rejects the
// document, so the failure is not a security hole — it is a correctness hole
// that surfaces at the far end of the wire, in someone else's logs, long after
// the producer has thrown away the inputs that caused it. Every case below
// therefore asserts twice: that the producer refuses, and that the document the
// producer would have emitted really is one the consumer rejects.

// ---------------------------------------------------------------------------
// "crit" (RFC 7515 §4.1.11)
// ---------------------------------------------------------------------------

// TestSignRejectsUnsatisfiableCrit covers a "crit" placed directly in
// SignOptions.Header rather than in SignOptions.Critical. Sign used to validate
// "crit" only when Critical was non-empty, so this route emitted a JWS whose
// "crit" names a parameter that is not in the header — which RFC 7515 §4.1.11
// makes a hard verification failure.
func TestSignRejectsUnsatisfiableCrit(t *testing.T) {
	requireKeys(t)
	for name, header := range map[string]map[string]any{
		"parameter not present": {"crit": []string{"exp-ext"}},
		"empty crit":            {"crit": []string{}},
		"registered name":       {"crit": []string{"kid"}, "kid": "k"},
		"crit is not an array":  {"crit": "exp-ext", "exp-ext": 1},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Sign([]byte("x"), testKeys.oct32, SignOptions{
				Algorithm: HS256,
				Header:    header,
			})
			if !errors.Is(err, ErrInvalidCrit) {
				t.Fatalf("Sign: err = %v, want ErrInvalidCrit", err)
			}
		})
	}
}

// TestSignAcceptsSatisfiedCritInHeader is the other half of the guard: a "crit"
// supplied through Header is fine when the named parameter is actually there,
// and the resulting JWS verifies once the caller declares the extension.
func TestSignAcceptsSatisfiedCritInHeader(t *testing.T) {
	requireKeys(t)
	token, err := Sign([]byte("x"), testKeys.oct32, SignOptions{
		Algorithm: HS256,
		Header:    map[string]any{"crit": []string{"exp-ext"}, "exp-ext": 1},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, _, err := VerifyWithOptions(token, testKeys.oct32, VerifyOptions{
		KnownCritical: []string{"exp-ext"},
	}); err != nil {
		t.Fatalf("VerifyWithOptions: %v", err)
	}
}

// TestEncryptRejectsUnsatisfiableCrit is the JWE mirror of
// TestSignRejectsUnsatisfiableCrit. DecryptWithOptions has always run
// checkCritical over the protected header; Encrypt did not, so a bad "crit"
// produced a token that only failed at the recipient.
func TestEncryptRejectsUnsatisfiableCrit(t *testing.T) {
	requireKeys(t)
	opts := EncryptOptions{
		Algorithm:  A256KW,
		Encryption: A256GCM,
		Header:     map[string]any{"crit": []string{"exp-ext"}},
	}
	if _, err := Encrypt([]byte("hello"), testKeys.oct32, opts); !errors.Is(err, ErrInvalidCrit) {
		t.Fatalf("Encrypt: err = %v, want ErrInvalidCrit", err)
	}
	if _, err := EncryptJSON([]byte("hello"), testKeys.oct32, opts); !errors.Is(err, ErrInvalidCrit) {
		t.Fatalf("EncryptJSON: err = %v, want ErrInvalidCrit", err)
	}

	// The document the producer would have emitted is genuinely unreadable:
	// build it by hand and watch Decrypt refuse it.
	opts.Header = map[string]any{"crit": []string{"exp-ext"}, "exp-ext": 1}
	token, err := Encrypt([]byte("hello"), testKeys.oct32, opts)
	if err != nil {
		t.Fatalf("Encrypt with a satisfied crit: %v", err)
	}
	if _, _, err := Decrypt(token, testKeys.oct32); !errors.Is(err, ErrInvalidCrit) {
		t.Fatalf("Decrypt without KnownCritical: err = %v, want ErrInvalidCrit", err)
	}
	if _, _, err := DecryptWithOptions(token, testKeys.oct32, DecryptOptions{
		KnownCritical: []string{"exp-ext"},
	}); err != nil {
		t.Fatalf("DecryptWithOptions: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Repeated header parameters (RFC 7515 §7.2.1, RFC 7516 §7.2.1)
// ---------------------------------------------------------------------------

// TestSignJSONRejectsRepeatedHeaderParameter covers a parameter present in both
// the protected and the unprotected header. Both RFCs require the member names
// to be disjoint, and mergeHeaders enforces that on the verify side, so a JWS
// built this way could never be verified by this package.
func TestSignJSONRejectsRepeatedHeaderParameter(t *testing.T) {
	requireKeys(t)
	_, err := SignJSON([]byte("x"), testKeys.oct32, SignOptions{
		Algorithm:   HS256,
		Header:      map[string]any{"cty": "example"},
		Unprotected: map[string]any{"cty": "example"},
	})
	if !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("SignJSON: err = %v, want ErrInvalidHeader", err)
	}
	if !strings.Contains(err.Error(), `"cty"`) {
		t.Errorf("SignJSON error %q does not name the repeated parameter", err)
	}
}

// TestEncryptJSONRejectsRepeatedHeaderParameter is the JWE mirror. The shared
// unprotected header is merged with the protected header at decryption time, so
// a repeat there is equally fatal.
func TestEncryptJSONRejectsRepeatedHeaderParameter(t *testing.T) {
	requireKeys(t)
	_, err := EncryptJSON([]byte("hello"), testKeys.oct32, EncryptOptions{
		Algorithm:   A256KW,
		Encryption:  A256GCM,
		Header:      map[string]any{"cty": "example"},
		Unprotected: map[string]any{"cty": "example"},
	})
	if !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("EncryptJSON: err = %v, want ErrInvalidHeader", err)
	}
}

// ---------------------------------------------------------------------------
// "zip" must be integrity protected (RFC 7516 §4.1.3)
// ---------------------------------------------------------------------------

// TestEncryptJSONRejectsRecipientZip covers the per-recipient half of the
// unprotected-"zip" guard. DecryptJSONWithOptions rejects "zip" in either the
// shared unprotected header or a per-recipient header; EncryptJSONMulti only
// screened the shared one, so a per-recipient "zip" produced a multi-recipient
// document that DecryptJSON refuses.
func TestEncryptJSONRejectsRecipientZip(t *testing.T) {
	requireKeys(t)
	_, err := EncryptJSONMulti([]byte("hello"), EncryptOptions{Encryption: A256GCM},
		Recipient{Key: testKeys.oct32, Algorithm: A256KW, Header: map[string]any{"zip": "DEF"}},
		Recipient{Key: testKeys.oct16, Algorithm: A128KW},
	)
	if !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("EncryptJSONMulti: err = %v, want ErrInvalidHeader", err)
	}
}

// ---------------------------------------------------------------------------
// Caller-supplied algorithm inputs in the JSON serialization
// ---------------------------------------------------------------------------

// TestEncryptJSONHonoursCallerSuppliedAlgorithmInputs pins the single-recipient
// JSON path to the compact path's behaviour for the header parameters that are
// algorithm *inputs*: PBES2's "p2s"/"p2c" and ECDH-ES's "apu"/"apv".
//
// EncryptJSONMulti used to hand the key-management algorithm a header holding
// only the per-recipient parameters, and merge the protected header in
// afterwards. That had two consequences, both visible here. A caller-supplied
// "p2s" was echoed back by the algorithm and the merge then rejected it as a
// "repeated" parameter, so EncryptJSON simply could not be called with an
// explicit salt. And "apu"/"apv" were invisible to the Concat KDF, so the CEK
// was derived without the PartyInfo the emitted header advertised — a document
// that decrypts to nothing at all.
func TestEncryptJSONHonoursCallerSuppliedAlgorithmInputs(t *testing.T) {
	requireKeys(t)
	plaintext := []byte("hello")

	t.Run("PBES2 p2s and p2c", func(t *testing.T) {
		password := []byte("correct horse battery staple")
		salt := EncodeSegment(randBytes(16))
		doc, err := EncryptJSON(plaintext, password, EncryptOptions{
			Algorithm:  PBES2_HS256_A128KW,
			Encryption: A128GCM,
			Header:     map[string]any{"p2s": salt, "p2c": MinPBES2Count},
		})
		if err != nil {
			t.Fatalf("EncryptJSON: %v", err)
		}
		got, header, err := DecryptJSON(doc, password)
		if err != nil {
			t.Fatalf("DecryptJSON: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("plaintext = %q, want %q", got, plaintext)
		}
		if header["p2s"] != salt {
			t.Errorf("p2s = %v, want the salt the caller supplied (%v)", header["p2s"], salt)
		}
		// json decodes the count as a float64; compare numerically.
		if c, err := headerInt(header["p2c"]); err != nil || c != MinPBES2Count {
			t.Errorf("p2c = %v (err %v), want %d", header["p2c"], err, MinPBES2Count)
		}
	})

	t.Run("ECDH-ES apu and apv", func(t *testing.T) {
		apu := EncodeSegment([]byte("Alice"))
		apv := EncodeSegment([]byte("Bob"))
		doc, err := EncryptJSON(plaintext, &testKeys.p256.PublicKey, EncryptOptions{
			Algorithm:  ECDH_ES_A128KW,
			Encryption: A128GCM,
			Header:     map[string]any{"apu": apu, "apv": apv},
		})
		if err != nil {
			t.Fatalf("EncryptJSON: %v", err)
		}
		got, header, err := DecryptJSON(doc, testKeys.p256)
		if err != nil {
			t.Fatalf("DecryptJSON: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("plaintext = %q, want %q", got, plaintext)
		}
		if header["apu"] != apu || header["apv"] != apv {
			t.Errorf("apu/apv = %v/%v, want %v/%v", header["apu"], header["apv"], apu, apv)
		}
	})

	t.Run("AESGCMKW iv is regenerated, never reused", func(t *testing.T) {
		// "iv" is an algorithm *output* for A128GCMKW, not an input. A caller
		// who sets it must be overruled: reusing a GCM nonce under one KEK
		// leaks the key stream and the authentication key.
		stale := EncodeSegment(make([]byte, 12))
		doc, err := EncryptJSON(plaintext, testKeys.oct16, EncryptOptions{
			Algorithm:  A128GCMKW,
			Encryption: A128GCM,
			Header:     map[string]any{"iv": stale},
		})
		if err != nil {
			t.Fatalf("EncryptJSON: %v", err)
		}
		got, header, err := DecryptJSON(doc, testKeys.oct16)
		if err != nil {
			t.Fatalf("DecryptJSON: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("plaintext = %q, want %q", got, plaintext)
		}
		if header["iv"] == stale {
			t.Error("the caller-supplied all-zero key-wrap IV was used verbatim")
		}
	})
}

// ---------------------------------------------------------------------------
// PBES2 "p2s" bounds (RFC 7518 §4.8.1.1)
// ---------------------------------------------------------------------------

// TestEncryptRejectsOversizedPBES2Salt covers the upper bound on "p2s".
// decryptKeyPBES2 has always enforced [8, MaxPBES2SaltInput]; encryptKeyPBES2
// enforced only the floor, so a caller supplying a larger salt got a token back
// that this package — and any other implementation with a comparable bound —
// will never unwrap.
func TestEncryptRejectsOversizedPBES2Salt(t *testing.T) {
	requireKeys(t)
	password := []byte("correct horse battery staple")
	oversized := EncodeSegment(randBytes(MaxPBES2SaltInput + 1))

	for _, fn := range []struct {
		name string
		call func(EncryptOptions) error
	}{
		{"Encrypt", func(o EncryptOptions) error { _, err := Encrypt([]byte("hi"), password, o); return err }},
		{"EncryptJSON", func(o EncryptOptions) error { _, err := EncryptJSON([]byte("hi"), password, o); return err }},
	} {
		t.Run(fn.name, func(t *testing.T) {
			err := fn.call(EncryptOptions{
				Algorithm:  PBES2_HS256_A128KW,
				Encryption: A128GCM,
				Header:     map[string]any{"p2s": oversized, "p2c": MinPBES2Count},
			})
			if !errors.Is(err, ErrInvalidHeader) {
				t.Fatalf("err = %v, want ErrInvalidHeader", err)
			}
		})
	}

	// A salt at the limit is accepted and round-trips, so the bound is a
	// boundary and not an off-by-one that rejects the largest legal salt.
	atLimit := EncodeSegment(randBytes(MaxPBES2SaltInput))
	token, err := Encrypt([]byte("hi"), password, EncryptOptions{
		Algorithm:  PBES2_HS256_A128KW,
		Encryption: A128GCM,
		Header:     map[string]any{"p2s": atLimit, "p2c": MinPBES2Count},
	})
	if err != nil {
		t.Fatalf("Encrypt with a %d-octet salt: %v", MaxPBES2SaltInput, err)
	}
	plaintext, _, err := Decrypt(token, password)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(plaintext) != "hi" {
		t.Errorf("plaintext = %q, want %q", plaintext, "hi")
	}

	// And the floor still holds on both sides.
	if _, err := Encrypt([]byte("hi"), password, EncryptOptions{
		Algorithm:  PBES2_HS256_A128KW,
		Encryption: A128GCM,
		Header:     map[string]any{"p2s": EncodeSegment(randBytes(7)), "p2c": MinPBES2Count},
	}); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("7-octet salt: err = %v, want ErrInvalidHeader", err)
	}
}
