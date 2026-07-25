package jose

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestRFC7520JWEJSON covers the RFC 7520 sections that publish only a JSON
// serialization: §5.10 (additional authenticated data), §5.11 (protecting
// specific header fields), §5.12 (protecting content only), and §5.13
// (multiple recipients).
func TestRFC7520JWEJSON(t *testing.T) {
	for _, tc := range []struct {
		name   string
		doc    string
		keyDoc string
		alg    string
	}{
		{"5.10 aad", rfc7520JWEJSONAAD_5_10, rfc7520KeyOctA128KW, A128KW},
		{"5.11 shared unprotected header", rfc7520JWEJSONSpecificHeaders_5_11, rfc7520KeyOctA128KW, A128KW},
		{"5.11 flattened", rfc7520JWEJSONSpecificHeadersFlat_5_11, rfc7520KeyOctA128KW, A128KW},
		{"5.12 no protected header", rfc7520JWEJSONContentOnly_5_12, rfc7520KeyOctA128KW, A128KW},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jwk := mustJWK(t, tc.keyDoc)
			plaintext, header, err := DecryptJSON([]byte(tc.doc), jwk)
			if err != nil {
				t.Fatalf("DecryptJSON: %v", err)
			}
			if string(plaintext) != rfc7520JWEPlaintext {
				t.Errorf("plaintext = %q", plaintext)
			}
			if got := Header(header).Algorithm(); got != tc.alg {
				t.Errorf("alg = %q, want %q", got, tc.alg)
			}
		})
	}
}

// TestRFC7520JWE510AAD checks specifically that the "aad" member participates
// in the authentication tag: stripping or altering it must break decryption.
func TestRFC7520JWE510AAD(t *testing.T) {
	jwk := mustJWK(t, rfc7520KeyOctA128KW)
	plaintext, _, err := DecryptJSON([]byte(rfc7520JWEJSONAAD_5_10), jwk)
	if err != nil {
		t.Fatalf("DecryptJSON: %v", err)
	}
	if string(plaintext) != rfc7520JWEPlaintext {
		t.Fatalf("plaintext = %q", plaintext)
	}

	var doc map[string]any
	if err := json.Unmarshal([]byte(rfc7520JWEJSONAAD_5_10), &doc); err != nil {
		t.Fatal(err)
	}
	aad, _ := doc["aad"].(string)
	if aad == "" {
		t.Fatal("the vector has no 'aad' member")
	}
	// The AAD text is the vCard of Figure 173.
	decoded, err := DecodeSegment(aad)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(decoded), "Meriadoc Brandybuck") {
		t.Errorf("decoded aad = %q", decoded)
	}

	for _, mutation := range []func(map[string]any){
		func(d map[string]any) { delete(d, "aad") },
		func(d map[string]any) { d["aad"] = EncodeSegment([]byte("something else")) },
	} {
		clone := map[string]any{}
		for k, v := range doc {
			clone[k] = v
		}
		mutation(clone)
		bad, err := json.Marshal(clone)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := DecryptJSON(bad, jwk); !errors.Is(err, ErrDecryptFailed) {
			t.Errorf("altering 'aad': err = %v, want ErrDecryptFailed", err)
		}
	}
}

// TestRFC7520JWE513MultiRecipient decrypts §5.13 with each of its three
// recipient keys, exercising RSA1_5, ECDH-ES+A256KW, and A256GCMKW over one
// shared content encryption.
func TestRFC7520JWE513MultiRecipient(t *testing.T) {
	for _, tc := range []struct {
		name   string
		keyDoc string
		alg    string
	}{
		{"recipient 1 RSA1_5", rfc7520KeyRsaEnc2048, RSA1_5},
		{"recipient 2 ECDH-ES+A256KW", rfc7520KeyEcP384Enc, ECDH_ES_A256KW},
		{"recipient 3 A256GCMKW", rfc7520KeyOctA256GCMKW, A256GCMKW},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jwk := mustJWK(t, tc.keyDoc)
			plaintext, header, err := DecryptJSON([]byte(rfc7520JWEJSONMultiRecipient_5_13), jwk)
			if err != nil {
				t.Fatalf("DecryptJSON: %v", err)
			}
			if string(plaintext) != rfc7520JWEPlaintext {
				t.Errorf("plaintext = %q", plaintext)
			}
			if got := Header(header).Algorithm(); got != tc.alg {
				t.Errorf("alg = %q, want %q", got, tc.alg)
			}
			if got := Header(header).Encryption(); got != A128CBC_HS256 {
				t.Errorf("enc = %q", got)
			}
		})
	}

	// A key that addresses none of the recipients must fail.
	if _, _, err := DecryptJSON([]byte(rfc7520JWEJSONMultiRecipient_5_13), make([]byte, 16)); err == nil {
		t.Error("expected decryption to fail with an unrelated key")
	}
}

// TestEncryptJSONRoundTrip checks the produce side of the JSON serialization,
// including the "aad" member and the shared unprotected header.
func TestEncryptJSONRoundTrip(t *testing.T) {
	jwk := mustJWK(t, rfc7520KeyOctA128KW)
	aad := []byte(`["vcard",[["fn",{},"text","Meriadoc Brandybuck"]]]`)

	data, err := EncryptJSON([]byte(rfc7520JWEPlaintext), jwk, EncryptOptions{
		Algorithm:                   A128KW,
		Encryption:                  A128GCM,
		AdditionalAuthenticatedData: aad,
		Unprotected:                 map[string]any{"cty": "text/plain"},
	})
	if err != nil {
		t.Fatalf("EncryptJSON: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if got, _ := doc["aad"].(string); got != EncodeSegment(aad) {
		t.Errorf("aad member = %q", got)
	}
	if _, ok := doc["unprotected"]; !ok {
		t.Error("the shared unprotected header was dropped")
	}

	plaintext, header, err := DecryptJSON(data, jwk)
	if err != nil {
		t.Fatalf("DecryptJSON: %v", err)
	}
	if string(plaintext) != rfc7520JWEPlaintext {
		t.Errorf("plaintext = %q", plaintext)
	}
	if got := Header(header).ContentType(); got != "text/plain" {
		t.Errorf("cty = %q", got)
	}

	// Neither of these belongs in the compact serialization.
	if _, err := Encrypt(nil, jwk, EncryptOptions{Algorithm: A128KW, Unprotected: map[string]any{"cty": "x"}}); !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("compact + unprotected: err = %v", err)
	}
	if _, err := Encrypt(nil, jwk, EncryptOptions{Algorithm: A128KW, AdditionalAuthenticatedData: aad}); !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("compact + aad: err = %v", err)
	}
}

// TestEncryptJSONMulti builds a three-recipient JWE of our own and decrypts it
// with each key.
func TestEncryptJSONMulti(t *testing.T) {
	rsaKey := mustJWK(t, rfc7520KeyRsaEnc2048)
	ecKey := mustJWK(t, rfc7520KeyEcP384Enc)
	octKey := mustJWK(t, rfc7520KeyOctA256GCMKW)

	rsaPub, err := rsaKey.Public()
	if err != nil {
		t.Fatal(err)
	}
	ecPub, err := ecKey.Public()
	if err != nil {
		t.Fatal(err)
	}

	data, err := EncryptJSONMulti([]byte(rfc7520JWEPlaintext),
		EncryptOptions{Encryption: A128CBC_HS256},
		Recipient{Key: rsaPub, Algorithm: RSA_OAEP_256, KeyID: rsaKey.Kid},
		Recipient{Key: ecPub, Algorithm: ECDH_ES_A256KW, KeyID: ecKey.Kid},
		Recipient{Key: octKey, Algorithm: A256GCMKW, KeyID: octKey.Kid},
	)
	if err != nil {
		t.Fatalf("EncryptJSONMulti: %v", err)
	}
	for _, jwk := range []*JWK{rsaKey, ecKey, octKey} {
		plaintext, header, err := DecryptJSON(data, jwk)
		if err != nil {
			t.Fatalf("DecryptJSON with kid %q: %v", jwk.Kid, err)
		}
		if string(plaintext) != rfc7520JWEPlaintext {
			t.Errorf("plaintext = %q", plaintext)
		}
		if got := Header(header).KeyID(); got != jwk.Kid {
			t.Errorf("kid = %q, want %q", got, jwk.Kid)
		}
	}

	// "dir" and direct ECDH-ES derive the CEK and cannot address several
	// recipients.
	_, err = EncryptJSONMulti([]byte("x"), EncryptOptions{Encryption: A128GCM},
		Recipient{Key: make([]byte, 16), Algorithm: Dir},
		Recipient{Key: octKey, Algorithm: A256GCMKW},
	)
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("dir with two recipients: err = %v", err)
	}
}

// TestDecryptJSONRejectsMixedForms checks that a document cannot present both
// the general and flattened shapes at once.
func TestDecryptJSONRejectsMixedForms(t *testing.T) {
	jwk := mustJWK(t, rfc7520KeyOctA128KW)
	var doc map[string]any
	if err := json.Unmarshal([]byte(rfc7520JWEJSONAAD_5_10), &doc); err != nil {
		t.Fatal(err)
	}
	doc["encrypted_key"] = "AAAA"
	bad, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := DecryptJSON(bad, jwk); !errors.Is(err, ErrMalformed) {
		t.Errorf("err = %v, want ErrMalformed", err)
	}
}

// TestDecryptJSONRejectsRepeatedHeaderParameters checks the RFC 7516 §7.2.1
// requirement that the protected, shared unprotected, and per-recipient
// unprotected headers be disjoint.
func TestDecryptJSONRejectsRepeatedHeaderParameters(t *testing.T) {
	jwk := mustJWK(t, rfc7520KeyOctA128KW)
	var doc map[string]any
	if err := json.Unmarshal([]byte(rfc7520JWEJSONSpecificHeaders_5_11), &doc); err != nil {
		t.Fatal(err)
	}
	// "enc" is already in the protected header; repeating it in the shared
	// unprotected header must be rejected rather than silently resolved.
	unprotected, _ := doc["unprotected"].(map[string]any)
	unprotected["enc"] = A128GCM
	bad, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := DecryptJSON(bad, jwk); !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("err = %v, want ErrInvalidHeader", err)
	}
}
