package jose

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
)

// This file holds one regression test per published security advisory, written
// against the fixed key and the fixed document each advisory publishes so that
// the vector in the advisory is the vector in the test. Every test here fails on
// v0.1.0.
//
//	GHSA-657x-hc2h-j7mj  unprotected {"b64":false} substitutes the payload
//	GHSA-4689-9mp2-q5rm  "crit" satisfied from an unprotected header
//	GHSA-w4qr-w6rh-v2mx  JWK "alg" pinning not enforced
//	GHSA-qvw9-rcpm-hhmw  JWK "use" not enforced
//	GHSA-89qh-5q5j-xrx9  JWK "key_ops" not enforced

// advisoryJWK is keys/oct-32.json from the parity suite, the key every advisory
// reproduction uses.
const advisoryJWK = `{"kty":"oct","k":"qbSot6YRXrsT-T9ytjbF654zxrkx9fTCCerXvJav324"}`

// advisoryPayload is the payload the published documents are signed over.
const advisoryPayload = "It's a dangerous business, Frodo, going out your door."

func advisoryKey(t *testing.T) *JWK {
	t.Helper()
	jwk, err := ParseJWK([]byte(advisoryJWK))
	if err != nil {
		t.Fatalf("ParseJWK: %v", err)
	}
	return jwk
}

// TestAdvisoryUnprotectedB64Substitution is GHSA-657x-hc2h-j7mj. The document is
// an ordinary, correctly signed HS256 JWS with b64 defaulting to true; only the
// unprotected "header" member was added, by someone holding no key at all.
// "b64" does not enter the signing input, so the MAC still checks out — and
// v0.1.0, which read "b64" from the merged header, then returned the base64url
// *text* of the payload instead of the payload. Verification must fail, and
// under no circumstances may a payload other than the signed one be returned.
func TestAdvisoryUnprotectedB64Substitution(t *testing.T) {
	const doc = `{
	  "payload": "SXQncyBhIGRhbmdlcm91cyBidXNpbmVzcywgRnJvZG8sIGdvaW5nIG91dCB5b3VyIGRvb3Iu",
	  "signatures": [
	    {
	      "header": { "b64": false },
	      "protected": "eyJhbGciOiJIUzI1NiJ9",
	      "signature": "SHOZXfrz9Xd5D1CyX-xk-GrGGQEuwrjXyxA6aCrsT9E"
	    }
	  ]
	}`
	got, hdr, err := VerifyJSON([]byte(doc), advisoryKey(t))
	if err == nil {
		t.Fatalf("the tampered document verified: payload=%q header=%v", got, hdr)
	}
	if !errors.Is(err, ErrUnprotectedB64) || !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("error = %v, want ErrUnprotectedB64 (and ErrInvalidHeader)", err)
	}
	if got != nil && !bytes.Equal(got, []byte(advisoryPayload)) {
		t.Errorf("a substituted payload was returned: %q", got)
	}
}

// TestAdvisoryCritSatisfiedFromUnprotected is GHSA-4689-9mp2-q5rm. Here the
// producer did defend itself: the protected header names "b64" in "crit", so a
// recipient is required to honour it. v0.1.0 looked the parameter up in the
// merged header, so the attacker's own unprotected {"b64":false} satisfied the
// very requirement that existed to stop them — and the payload substitution
// went through on a token whose signer had asked for exactly the opposite.
func TestAdvisoryCritSatisfiedFromUnprotected(t *testing.T) {
	const doc = `{
	  "payload": "SXQncyBhIGRhbmdlcm91cyBidXNpbmVzcywgRnJvZG8sIGdvaW5nIG91dCB5b3VyIGRvb3Iu",
	  "signatures": [
	    {
	      "header": { "b64": false },
	      "protected": "eyJhbGciOiJIUzI1NiIsImNyaXQiOlsiYjY0Il19",
	      "signature": "ppChox5SDDSKjeO7hsCj_RuoNiq-FenHSY0bnCTqIus"
	    }
	  ]
	}`
	got, hdr, err := VerifyJSON([]byte(doc), advisoryKey(t))
	if err == nil {
		t.Fatalf("the tampered document verified: payload=%q header=%v", got, hdr)
	}
	if got != nil && !bytes.Equal(got, []byte(advisoryPayload)) {
		t.Errorf("a substituted payload was returned: %q", got)
	}
}

// TestAdvisoryCritExtensionMustBeProtected is the general form of the same bug,
// with an extension parameter rather than "b64": a "crit" naming "myext" must
// not be satisfied by a "myext" the signature does not cover. The signature
// below is genuine, and identical for both documents — which is the point. If
// the unprotected copy counted, a recipient would act on a critical value an
// attacker rewrote freely.
func TestAdvisoryCritExtensionMustBeProtected(t *testing.T) {
	secret, err := advisoryKey(t).Key()
	if err != nil {
		t.Fatal(err)
	}
	protected, err := encodeHeader(map[string]any{"alg": HS256, "crit": []string{"myext"}})
	if err != nil {
		t.Fatal(err)
	}
	payloadSeg := EncodeSegment([]byte(advisoryPayload))
	mac := hmac.New(sha256.New, secret.([]byte))
	mac.Write(signingInput(protected, payloadSeg))
	sig := EncodeSegment(mac.Sum(nil))

	for _, value := range []any{"attacker-chosen", 42} {
		doc, err := json.Marshal(map[string]any{
			"payload":   payloadSeg,
			"protected": protected,
			"header":    map[string]any{"myext": value},
			"signature": sig,
		})
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = VerifyJSONWithOptions(doc, secret, VerifyOptions{
			Algorithms:    []string{HS256},
			KnownCritical: []string{"myext"},
		})
		if err == nil {
			t.Fatalf("unprotected myext=%v satisfied 'crit'", value)
		}
		if !errors.Is(err, ErrUnprotectedCritical) || !errors.Is(err, ErrInvalidCrit) {
			t.Errorf("myext=%v: error = %v, want ErrUnprotectedCritical (and ErrInvalidCrit)", value, err)
		}
	}
}

// TestAdvisoryCritInProtectedStillVerifies is the positive counterpart: the same
// document with the critical parameter where it belongs — in the protected
// header, covered by the signature — must verify and must report the value.
func TestAdvisoryCritInProtectedStillVerifies(t *testing.T) {
	key := advisoryKey(t)
	token, err := Sign([]byte(advisoryPayload), key, SignOptions{
		Algorithm: HS256,
		Header:    map[string]any{"myext": "signed"},
		Critical:  []string{"myext"},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	got, hdr, err := VerifyWithOptions(token, key, VerifyOptions{
		Algorithms:    []string{HS256},
		KnownCritical: []string{"myext"},
	})
	if err != nil {
		t.Fatalf("VerifyWithOptions: %v", err)
	}
	if string(got) != advisoryPayload {
		t.Errorf("payload = %q, want %q", got, advisoryPayload)
	}
	if hdr["myext"] != "signed" {
		t.Errorf("header myext = %v, want \"signed\"", hdr["myext"])
	}
}

// TestAdvisorySignRejectsCriticalInUnprotected is the producer side: a caller who
// declares a parameter critical and then puts it in the unprotected header is
// building the document the two advisories above exploit. Refuse it here rather
// than emit a JWS whose critical parameter nothing authenticates.
func TestAdvisorySignRejectsCriticalInUnprotected(t *testing.T) {
	_, err := SignJSON([]byte(advisoryPayload), advisoryKey(t), SignOptions{
		Algorithm:   HS256,
		Critical:    []string{"myext"},
		Unprotected: map[string]any{"myext": "unsigned"},
	})
	if !errors.Is(err, ErrInvalidCrit) {
		t.Fatalf("error = %v, want ErrInvalidCrit", err)
	}
}

// TestAdvisoryJWKAlgIsPinned is GHSA-w4qr-w6rh-v2mx. A key that pins itself to
// HS512 must not be used with HS256 in either direction; v0.1.0 treated "alg"
// as a default for SignOptions.Algorithm and never checked it, so the choice of
// algorithm was silently handed to whoever wrote the header.
func TestAdvisoryJWKAlgIsPinned(t *testing.T) {
	key := advisoryKey(t)
	key.Alg = HS512

	// The HS256 token from the advisory, over advisoryPayload.
	const hs256Token = "eyJhbGciOiJIUzI1NiJ9.SXQncyBhIGRhbmdlcm91cyBidXNpbmVzcywgRnJvZG8sIGdvaW5nIG91dCB5b3VyIGRvb3Iu.SHOZXfrz9Xd5D1CyX-xk-GrGGQEuwrjXyxA6aCrsT9E"

	if tok, err := Sign([]byte(advisoryPayload), key, SignOptions{Algorithm: HS256}); !errors.Is(err, ErrKeyAlgMismatch) {
		t.Errorf("Sign: error = %v (token %q), want ErrKeyAlgMismatch", err, tok)
	}
	if _, _, err := Verify(hs256Token, key); !errors.Is(err, ErrKeyAlgMismatch) {
		t.Errorf("Verify: error = %v, want ErrKeyAlgMismatch", err)
	}
	if !errors.Is(ErrKeyAlgMismatch, ErrInvalidKey) {
		t.Error("ErrKeyAlgMismatch must match ErrInvalidKey")
	}

	// Positive: the algorithm the key names works, and is what Sign infers.
	tok, err := Sign([]byte(advisoryPayload), key, SignOptions{Algorithm: HS512})
	if err != nil {
		t.Fatalf("Sign with the pinned algorithm: %v", err)
	}
	if _, hdr, err := Verify(tok, key); err != nil {
		t.Fatalf("Verify with the pinned algorithm: %v", err)
	} else if hdr["alg"] != HS512 {
		t.Errorf("alg = %v, want %v", hdr["alg"], HS512)
	}
	if _, err := Sign([]byte(advisoryPayload), key, SignOptions{}); err != nil {
		t.Errorf("Sign with an inferred algorithm: %v", err)
	}
}

// TestAdvisoryJWKUseIsEnforced is GHSA-qvw9-rcpm-hhmw: a key published for
// encryption is not a signing key, whatever the caller asks for.
func TestAdvisoryJWKUseIsEnforced(t *testing.T) {
	const hs256Token = "eyJhbGciOiJIUzI1NiJ9.SXQncyBhIGRhbmdlcm91cyBidXNpbmVzcywgRnJvZG8sIGdvaW5nIG91dCB5b3VyIGRvb3Iu.SHOZXfrz9Xd5D1CyX-xk-GrGGQEuwrjXyxA6aCrsT9E"

	encKey := advisoryKey(t)
	encKey.Use = UseEnc
	if tok, err := Sign([]byte(advisoryPayload), encKey, SignOptions{Algorithm: HS256}); !errors.Is(err, ErrKeyUseMismatch) {
		t.Errorf("Sign with use=enc: error = %v (token %q), want ErrKeyUseMismatch", err, tok)
	}
	if _, _, err := Verify(hs256Token, encKey); !errors.Is(err, ErrKeyUseMismatch) {
		t.Errorf("Verify with use=enc: error = %v, want ErrKeyUseMismatch", err)
	}
	if !errors.Is(ErrKeyUseMismatch, ErrInvalidKey) {
		t.Error("ErrKeyUseMismatch must match ErrInvalidKey")
	}

	// Positive: the same key material with the matching "use" signs, verifies,
	// and round-trips.
	sigKey := advisoryKey(t)
	sigKey.Use = UseSig
	tok, err := Sign([]byte(advisoryPayload), sigKey, SignOptions{Algorithm: HS256})
	if err != nil {
		t.Fatalf("Sign with use=sig: %v", err)
	}
	got, _, err := Verify(tok, sigKey)
	if err != nil {
		t.Fatalf("Verify with use=sig: %v", err)
	}
	if string(got) != advisoryPayload {
		t.Errorf("payload = %q, want %q", got, advisoryPayload)
	}

	// And the mirror image: a signing key must not encrypt.
	if _, err := Encrypt([]byte(advisoryPayload), sigKey, EncryptOptions{
		Algorithm: A256KW, Encryption: A256GCM,
	}); !errors.Is(err, ErrKeyUseMismatch) {
		t.Errorf("Encrypt with use=sig: error = %v, want ErrKeyUseMismatch", err)
	}
}

// TestAdvisoryJWKKeyOpsIsEnforced is GHSA-89qh-5q5j-xrx9: "key_ops" is the
// finer-grained form of "use", and an encrypt/decrypt-only key must neither
// sign nor verify.
func TestAdvisoryJWKKeyOpsIsEnforced(t *testing.T) {
	const hs256Token = "eyJhbGciOiJIUzI1NiJ9.SXQncyBhIGRhbmdlcm91cyBidXNpbmVzcywgRnJvZG8sIGdvaW5nIG91dCB5b3VyIGRvb3Iu.SHOZXfrz9Xd5D1CyX-xk-GrGGQEuwrjXyxA6aCrsT9E"

	key := advisoryKey(t)
	key.KeyOps = []string{"encrypt", "decrypt"}
	if tok, err := Sign([]byte(advisoryPayload), key, SignOptions{Algorithm: HS256}); !errors.Is(err, ErrKeyOpsMismatch) {
		t.Errorf("Sign with key_ops=[encrypt,decrypt]: error = %v (token %q), want ErrKeyOpsMismatch", err, tok)
	}
	if _, _, err := Verify(hs256Token, key); !errors.Is(err, ErrKeyOpsMismatch) {
		t.Errorf("Verify with key_ops=[encrypt,decrypt]: error = %v, want ErrKeyOpsMismatch", err)
	}
	if !errors.Is(ErrKeyOpsMismatch, ErrInvalidKey) {
		t.Error("ErrKeyOpsMismatch must match ErrInvalidKey")
	}

	// Positive: the operations the key does permit are permitted.
	signer := advisoryKey(t)
	signer.KeyOps = []string{"sign", "verify"}
	tok, err := Sign([]byte(advisoryPayload), signer, SignOptions{Algorithm: HS256})
	if err != nil {
		t.Fatalf("Sign with key_ops=[sign,verify]: %v", err)
	}
	if _, _, err := Verify(tok, signer); err != nil {
		t.Fatalf("Verify with key_ops=[sign,verify]: %v", err)
	}
}

// TestAdvisoryUnrestrictedKeyRoundTrip is the baseline the four fixes above must
// not disturb: a key that states no "alg", "use", or "key_ops" is unrestricted,
// and an ordinary JWS round-trips in both the compact and the JSON
// serialization.
func TestAdvisoryUnrestrictedKeyRoundTrip(t *testing.T) {
	key := advisoryKey(t)
	payload := []byte(advisoryPayload)

	token, err := Sign(payload, key, SignOptions{Algorithm: HS256})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	got, hdr, err := Verify(token, key)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("compact payload = %q, want %q", got, payload)
	}
	if hdr["alg"] != HS256 {
		t.Errorf("alg = %v, want %v", hdr["alg"], HS256)
	}

	doc, err := SignJSON(payload, key, SignOptions{Algorithm: HS256})
	if err != nil {
		t.Fatalf("SignJSON: %v", err)
	}
	got, _, err = VerifyJSON(doc, key)
	if err != nil {
		t.Fatalf("VerifyJSON: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("JSON payload = %q, want %q", got, payload)
	}
}
