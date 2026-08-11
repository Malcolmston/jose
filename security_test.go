package jose

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
)

// This file holds the adversarial tests: every case here is a way a JOSE
// implementation has historically been broken. They are grouped by the property
// they defend, and each one states the attack it stands in for.

// ---------------------------------------------------------------------------
// RFC 7797 "b64" must be integrity protected
// ---------------------------------------------------------------------------

// TestVerifyJSONRejectsUnprotectedB64 covers a payload-substitution attack. The
// "b64" parameter decides whether the payload member is base64url-decoded before
// being returned, but it does not enter the signing input — the signature covers
// the payload *segment* either way. So a "b64":false grafted onto the
// unauthenticated per-signature header changes what Verify hands back while the
// signature still checks out: a caller who signed the octets {"amount":1}
// receives the ASCII "eyJhbW91bnQiOjF9" instead. RFC 7797 §6 requires "b64" to
// be integrity protected precisely because of this.
func TestVerifyJSONRejectsUnprotectedB64(t *testing.T) {
	secret := testKeys.oct32
	payload := []byte(`{"amount":1}`)

	for _, form := range []string{"general", "flattened"} {
		t.Run(form, func(t *testing.T) {
			doc, err := SignJSON(payload, secret, SignOptions{Algorithm: HS256})
			if err != nil {
				t.Fatalf("SignJSON: %v", err)
			}
			var m map[string]any
			if err := json.Unmarshal(doc, &m); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if form == "flattened" {
				sig := m["signatures"].([]any)[0].(map[string]any)
				delete(m, "signatures")
				m["protected"] = sig["protected"]
				m["signature"] = sig["signature"]
				m["header"] = map[string]any{"b64": false}
			} else {
				sig := m["signatures"].([]any)[0].(map[string]any)
				sig["header"] = map[string]any{"b64": false}
			}
			tampered, err := json.Marshal(m)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			got, _, err := VerifyJSONWithOptions(tampered, secret,
				VerifyOptions{Algorithms: []string{HS256}, KnownCritical: []string{"b64"}})
			if err == nil {
				t.Fatalf("tampered document verified and returned %q; 'b64' in an "+
					"unprotected header must be rejected", got)
			}
			if !errors.Is(err, ErrInvalidHeader) {
				t.Errorf("error = %v, want ErrInvalidHeader", err)
			}
			// The decisive property: whatever the error, the caller must never
			// be handed a payload other than the signed one.
			if got != nil && !bytes.Equal(got, payload) {
				t.Errorf("returned a substituted payload %q", got)
			}
		})
	}
}

// TestVerifyRejectsB64WithoutCrit checks RFC 7797 §3: "b64" is only meaningful
// when the recipient is forced to understand it, which is what listing it in
// "crit" achieves. A protected {"alg":"HS256","b64":false} with no "crit" would
// otherwise let a producer quietly change the payload encoding.
func TestVerifyRejectsB64WithoutCrit(t *testing.T) {
	secret := testKeys.oct32
	protected, err := encodeHeader(map[string]any{"alg": HS256, "b64": false})
	if err != nil {
		t.Fatal(err)
	}
	payload := "unencoded"
	mac := hmac.New(sha256.New, secret)
	mac.Write(signingInput(protected, payload))
	token := protected + "." + payload + "." + EncodeSegment(mac.Sum(nil))

	// The signature itself is genuine; only the missing "crit" is wrong.
	_, _, err = VerifyWithOptions(token, secret, VerifyOptions{KnownCritical: []string{"b64"}})
	if !errors.Is(err, ErrInvalidCrit) {
		t.Fatalf("error = %v, want ErrInvalidCrit", err)
	}
}

// TestVerifyAcceptsB64WithCrit is the positive counterpart: the RFC 7797 §4.2
// vector, whose protected header does list "b64" in "crit", must still verify.
func TestVerifyAcceptsB64WithCrit(t *testing.T) {
	// RFC 7797 §4.2, verbatim.
	const (
		key       = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
		protected = "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19"
		signature = "A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY"
		payload   = "$.02"
	)
	secret, err := DecodeSegment(key)
	if err != nil {
		t.Fatal(err)
	}
	doc := `{"payload":"` + payload + `","protected":"` + protected + `","signature":"` + signature + `"}`
	got, hdr, err := VerifyJSONWithOptions([]byte(doc), secret,
		VerifyOptions{Algorithms: []string{HS256}, KnownCritical: []string{"b64"}})
	if err != nil {
		t.Fatalf("VerifyJSONWithOptions: %v", err)
	}
	if string(got) != payload {
		t.Errorf("payload = %q, want %q", got, payload)
	}
	if b64, _ := hdr["b64"].(bool); b64 {
		t.Errorf("header b64 = %v, want false", hdr["b64"])
	}
}

// ---------------------------------------------------------------------------
// Empty and degenerate keys
// ---------------------------------------------------------------------------

// TestVerifyRejectsEmptyHMACSecret covers the fail-open case where a secret
// resolves to nothing — an unset environment variable, a truncated config value,
// a zero-value struct field. HMAC keyed with zero octets is a public function,
// so anyone can compute a tag that hmac.Equal accepts; the comparison being
// constant-time does not help when the attacker knows the key. Sign has always
// refused an empty secret, which made verify's silence worse: the system would
// look healthy while accepting forged tokens.
func TestVerifyRejectsEmptyHMACSecret(t *testing.T) {
	for _, alg := range []string{HS256, HS384, HS512} {
		for _, secret := range [][]byte{{}, nil} {
			a := sigAlgs[alg]
			protected, err := encodeHeader(map[string]any{"alg": alg})
			if err != nil {
				t.Fatal(err)
			}
			pl := EncodeSegment([]byte("attacker payload"))
			// Forge the tag the way an attacker would: with the empty key.
			mac := hmac.New(a.hash.New, secret)
			mac.Write(signingInput(protected, pl))
			token := protected + "." + pl + "." + EncodeSegment(mac.Sum(nil))

			if _, _, err := Verify(token, secret); !errors.Is(err, ErrInvalidKey) {
				t.Errorf("%s with a %d-octet secret: error = %v, want ErrInvalidKey",
					alg, len(secret), err)
			}
			doc, _ := json.Marshal(map[string]any{
				"payload":    pl,
				"protected":  protected,
				"signature":  strings.Split(token, ".")[2],
				"signatures": nil,
			})
			if _, _, err := VerifyJSON(doc, secret); err == nil {
				t.Errorf("%s JSON with a %d-octet secret verified", alg, len(secret))
			}
			// Signing must stay refused too, so the asymmetry cannot reappear.
			if _, err := Sign([]byte("x"), secret, SignOptions{Algorithm: alg}); !errors.Is(err, ErrInvalidKey) {
				t.Errorf("Sign %s with a %d-octet secret: error = %v", alg, len(secret), err)
			}
		}
	}
}

// TestVerifyRejectsEmptySignature checks that an absent signature cannot be read
// as "nothing to compare". The compact form can carry an empty third segment and
// the JSON form an empty "signature" member; both must fail.
func TestVerifyRejectsEmptySignature(t *testing.T) {
	secret := testKeys.oct32
	token, err := Sign([]byte("payload"), secret, SignOptions{Algorithm: HS256})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")

	if _, _, err := Verify(parts[0]+"."+parts[1]+".", secret); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("compact with an empty signature: error = %v, want ErrSignatureInvalid", err)
	}
	doc := `{"payload":"` + parts[1] + `","signatures":[{"protected":"` + parts[0] + `","signature":""}]}`
	if _, _, err := VerifyJSON([]byte(doc), secret); err == nil {
		t.Error("JSON with an empty signature verified")
	}
	// An omitted "signature" member is the same thing spelled differently.
	doc = `{"payload":"` + parts[1] + `","signatures":[{"protected":"` + parts[0] + `"}]}`
	if _, _, err := VerifyJSON([]byte(doc), secret); err == nil {
		t.Error("JSON with an omitted signature verified")
	}
}

// ---------------------------------------------------------------------------
// Algorithm confusion
// ---------------------------------------------------------------------------

// TestAlgorithmConfusion is the classic HS256/RS256 attack: a token whose header
// claims HMAC, presented to a verifier holding an asymmetric *public* key. If
// the verifier trusted the header's "alg" it would MAC the token with the public
// key — which the attacker also has — and accept. Every algorithm here
// type-asserts its key, so the public key never reaches an HMAC.
func TestAlgorithmConfusion(t *testing.T) {
	pubKeys := map[string]any{
		"rsa":     &testKeys.rsa.PublicKey,
		"p256":    &testKeys.p256.PublicKey,
		"ed25519": testKeys.ed.Public(),
	}
	for name, pub := range pubKeys {
		t.Run(name, func(t *testing.T) {
			// The attacker MACs with the DER/raw encoding of the public key,
			// the shape this attack normally takes.
			material, err := json.Marshal(pub)
			if err != nil {
				t.Fatal(err)
			}
			forged, err := Sign([]byte(`{"admin":true}`), material, SignOptions{Algorithm: HS256})
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := Verify(forged, pub); !errors.Is(err, ErrInvalidKeyType) {
				t.Errorf("HS256 token verified against a %s public key: error = %v", name, err)
			}
			// And the reverse direction: a genuine asymmetric token must not be
			// accepted when the caller has pinned HMAC.
			var signKey any = testKeys.rsa
			alg := RS256
			switch name {
			case "p256":
				signKey, alg = testKeys.p256, ES256
			case "ed25519":
				signKey, alg = testKeys.ed, EdDSA
			}
			token, err := Sign([]byte("x"), signKey, SignOptions{Algorithm: alg})
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = VerifyWithOptions(token, pub, VerifyOptions{Algorithms: []string{HS256}})
			if !errors.Is(err, ErrSignatureInvalid) {
				t.Errorf("%s token accepted under an HS256 allow-list: error = %v", alg, err)
			}
		})
	}
}

// TestVerifyRejectsNoneEverywhere checks that the unsecured algorithm has no way
// in: not through the compact form, not through either JSON form, and not by a
// caller naming it in the allow-list.
func TestVerifyRejectsNoneEverywhere(t *testing.T) {
	protected, err := encodeHeader(map[string]any{"alg": None})
	if err != nil {
		t.Fatal(err)
	}
	pl := EncodeSegment([]byte(`{"admin":true}`))

	for _, token := range []string{
		protected + "." + pl + ".",
		protected + "." + pl + "." + EncodeSegment([]byte("anything")),
	} {
		if _, _, err := Verify(token, testKeys.oct32); err == nil {
			t.Errorf("compact 'none' token verified: %q", token)
		}
	}
	doc := `{"payload":"` + pl + `","protected":"` + protected + `","signature":"` +
		EncodeSegment([]byte("x")) + `"}`
	if _, _, err := VerifyJSON([]byte(doc), testKeys.oct32); !errors.Is(err, ErrNoneAlgDisallowed) {
		t.Errorf("JSON 'none' token: error = %v, want ErrNoneAlgDisallowed", err)
	}
	// Opting in explicitly must not help.
	_, _, err = VerifyWithOptions(protected+"."+pl+".", testKeys.oct32,
		VerifyOptions{Algorithms: []string{None}})
	if !errors.Is(err, ErrNoneAlgDisallowed) {
		t.Errorf("allow-listing 'none': error = %v, want ErrNoneAlgDisallowed", err)
	}
	// Signing it must be impossible too.
	if _, err := Sign([]byte("x"), testKeys.oct32, SignOptions{Algorithm: None}); !errors.Is(err, ErrNoneAlgDisallowed) {
		t.Errorf("Sign with 'none': error = %v", err)
	}
}

// TestVerifyJSONRejectsMixedForms rejects a document holding both "signatures"
// and the flattened members. Accepting it would let an attacker staple an
// unauthenticated top-level header onto a genuine multi-signature document.
func TestVerifyJSONRejectsMixedForms(t *testing.T) {
	secret := testKeys.oct32
	doc, err := SignJSON([]byte("payload"), secret, SignOptions{Algorithm: HS256})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(doc, &m); err != nil {
		t.Fatal(err)
	}
	sig := m["signatures"].([]any)[0].(map[string]any)
	m["protected"] = sig["protected"]
	m["signature"] = sig["signature"]
	mixed, _ := json.Marshal(m)
	if _, _, err := VerifyJSON(mixed, secret); !errors.Is(err, ErrMalformed) {
		t.Errorf("mixed-form JWS: error = %v, want ErrMalformed", err)
	}
}

// TestMultiSignatureIsIndependentlyVerified checks that a multi-signature JWS
// does not let one good signature vouch for a tampered sibling, and that a
// document where *every* signature is broken fails.
func TestMultiSignatureIsIndependentlyVerified(t *testing.T) {
	payload := []byte("shared payload")
	doc, err := SignJSONMulti(payload,
		Signer{Key: testKeys.oct32, Options: SignOptions{Algorithm: HS256}},
		Signer{Key: testKeys.rsa, Options: SignOptions{Algorithm: RS256}},
	)
	if err != nil {
		t.Fatal(err)
	}
	// Each key sees its own signature and nothing else.
	for _, key := range []any{testKeys.oct32, &testKeys.rsa.PublicKey} {
		got, _, err := VerifyJSON(doc, key)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("VerifyJSON: %v, payload %q", err, got)
		}
	}
	// Corrupt the RSA signature; the HMAC one must still verify and the RSA
	// key must now fail rather than ride along on it.
	var m map[string]any
	if err := json.Unmarshal(doc, &m); err != nil {
		t.Fatal(err)
	}
	sigs := m["signatures"].([]any)
	rsaSig := sigs[1].(map[string]any)
	rsaSig["signature"] = EncodeSegment(bytes.Repeat([]byte{0}, 256))
	broken, _ := json.Marshal(m)
	if _, _, err := VerifyJSON(broken, testKeys.oct32); err != nil {
		t.Errorf("HMAC signature should still verify: %v", err)
	}
	if _, _, err := VerifyJSON(broken, &testKeys.rsa.PublicKey); err == nil {
		t.Error("a corrupt RSA signature verified")
	}
}

// ---------------------------------------------------------------------------
// Canonical base64url
// ---------------------------------------------------------------------------

// TestDecodeSegmentIsCanonical pins the decoder to exactly one spelling per
// value. A lenient decoder makes the serialized token malleable: with four spare
// bits in the final quantum of a 64-octet ECDSA signature, sixteen distinct
// token strings decode to the same signature and all verify — which breaks
// anything keying a replay cache, audit log, or revocation list on the token.
func TestDecodeSegmentIsCanonical(t *testing.T) {
	// "-_8" is the canonical encoding of {0xFB, 0xFF}.
	if _, err := DecodeSegment("-_8"); err != nil {
		t.Fatalf("canonical segment rejected: %v", err)
	}
	for _, bad := range []struct{ seg, why string }{
		{"-_8=", "padding"},
		{"-_9", "non-zero unused bits in the final quantum"},
		{"aa", "non-zero unused bits in a two-character quantum"},
		{"+/8", "standard alphabet instead of base64url"},
		{"-_ 8", "embedded whitespace"},
		{"-_8\n", "trailing newline"},
		{"-", "a one-character quantum, which encodes nothing"},
		{"!!!", "characters outside the alphabet"},
	} {
		if _, err := DecodeSegment(bad.seg); err == nil {
			t.Errorf("DecodeSegment(%q) accepted; %s must be rejected", bad.seg, bad.why)
		}
	}
	// "aQ" is the canonical two-character encoding of 0x69 — its four unused
	// bits are zero — and must still decode. "aa" above is the same octet spelt
	// with those bits set, which is exactly what strict mode exists to reject.
	if b, err := DecodeSegment("aQ"); err != nil || !bytes.Equal(b, []byte{0x69}) {
		t.Errorf("DecodeSegment(%q) = %x, %v", "aQ", b, err)
	}
}

// TestNonCanonicalSignatureIsRejected exercises the malleability above end to
// end: flipping an unused bit in the signature's final base64url character must
// not produce a second token string that verifies.
func TestNonCanonicalSignatureIsRejected(t *testing.T) {
	token, err := Sign([]byte("payload"), testKeys.p256, SignOptions{Algorithm: ES256})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	sig := parts[2]
	// The last character of an 86-character segment carries four unused bits;
	// bumping it by one leaves the decoded octets unchanged in a lenient
	// decoder.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, sig[len(sig)-1])
	if last < 0 {
		t.Fatalf("unexpected signature character %q", sig[len(sig)-1])
	}
	variant := sig[:len(sig)-1] + string(alphabet[last+1])
	if variant == sig {
		t.Fatal("failed to build a variant encoding")
	}
	mutated := parts[0] + "." + parts[1] + "." + variant
	if _, _, err := Verify(mutated, &testKeys.p256.PublicKey); err == nil {
		t.Errorf("a second encoding of the same signature verified:\n %s\n %s", token, mutated)
	}
}

// ---------------------------------------------------------------------------
// JWK restrictions and private-material hygiene
// ---------------------------------------------------------------------------

// TestJWKUsageIsEnforced checks RFC 7517 §4.2–§4.4: a key that declares what it
// is for must not be used for anything else. Publishing one key for signing and
// another for encryption is only a boundary if the library honours it.
func TestJWKUsageIsEnforced(t *testing.T) {
	sigKey, err := FromKey(testKeys.oct32)
	if err != nil {
		t.Fatal(err)
	}
	sigKey.Use = UseSig
	sigKey.Alg = HS256

	// Right use, right alg: works.
	token, err := Sign([]byte("x"), sigKey, SignOptions{Algorithm: HS256})
	if err != nil {
		t.Fatalf("Sign with a matching JWK: %v", err)
	}
	if _, _, err := Verify(token, sigKey); err != nil {
		t.Fatalf("Verify with a matching JWK: %v", err)
	}

	// Wrong alg for the same key.
	wrongAlg := *sigKey
	wrongAlg.Alg = HS512
	if _, err := Sign([]byte("x"), &wrongAlg, SignOptions{Algorithm: HS256}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Sign with alg mismatch: error = %v, want ErrInvalidKey", err)
	}
	if _, _, err := Verify(token, &wrongAlg); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Verify with alg mismatch: error = %v, want ErrInvalidKey", err)
	}

	// A signing key must not be usable for encryption.
	if _, err := Encrypt([]byte("x"), sigKey, EncryptOptions{Algorithm: A256KW, Encryption: A256GCM}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Encrypt with a use=sig JWK: error = %v, want ErrInvalidKey", err)
	}

	// And an encryption key must not be usable for signing.
	encKey, err := FromKey(testKeys.oct32)
	if err != nil {
		t.Fatal(err)
	}
	encKey.Use = UseEnc
	encKey.Alg = A256KW
	if _, err := Sign([]byte("x"), encKey, SignOptions{Algorithm: HS256}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Sign with a use=enc JWK: error = %v, want ErrInvalidKey", err)
	}

	// key_ops is the finer-grained form of the same rule.
	verifyOnly := *sigKey
	verifyOnly.KeyOps = []string{"verify"}
	if _, err := Sign([]byte("x"), &verifyOnly, SignOptions{Algorithm: HS256}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Sign with key_ops=[verify]: error = %v, want ErrInvalidKey", err)
	}
	if _, _, err := Verify(token, &verifyOnly); err != nil {
		t.Errorf("Verify with key_ops=[verify]: %v", err)
	}
}

// TestJWKPublicDoesNotLeakPrivateMaterial checks that the published form of a
// key carries no secret. Public must strip every private member, for every key
// type, and the JSON it marshals to must not contain them either.
func TestJWKPublicDoesNotLeakPrivateMaterial(t *testing.T) {
	privateMembers := []string{`"d"`, `"p"`, `"q"`, `"dp"`, `"dq"`, `"qi"`, `"k"`}
	for _, key := range []any{
		testKeys.rsa, testKeys.p256, testKeys.p384, testKeys.p521,
		testKeys.ed, testKeys.x25519,
	} {
		jwk, err := FromKey(key)
		if err != nil {
			t.Fatalf("FromKey(%T): %v", key, err)
		}
		if !jwk.IsPrivate() {
			t.Fatalf("FromKey(%T) produced a JWK that does not report as private", key)
		}
		pub, err := jwk.Public()
		if err != nil {
			t.Fatalf("Public(%T): %v", key, err)
		}
		if pub.IsPrivate() {
			t.Errorf("Public(%T) still reports as private", key)
		}
		raw, err := json.Marshal(pub)
		if err != nil {
			t.Fatal(err)
		}
		for _, member := range privateMembers {
			if bytes.Contains(raw, []byte(member+":")) {
				t.Errorf("Public(%T) marshalled %s: %s", key, member, raw)
			}
		}
		// Public must not mutate the original.
		if !jwk.IsPrivate() {
			t.Errorf("Public(%T) stripped the receiver", key)
		}
		// The public JWK must still resolve, and to a public key.
		resolved, err := pub.Key()
		if err != nil {
			t.Errorf("Public(%T).Key(): %v", key, err)
		}
		if _, ok := resolved.(interface{ Public() any }); ok {
			t.Errorf("Public(%T).Key() returned a private key %T", key, resolved)
		}
	}
	// A symmetric key has no public form; saying so beats returning the secret.
	oct, err := FromKey(testKeys.oct32)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oct.Public(); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("oct Public(): error = %v, want ErrInvalidKey", err)
	}
}

// TestJWKRejectsMismatchedParameters checks that a key type and its parameters
// must agree — a JWK naming one "kty" while carrying another's members, or an EC
// point that is not on the curve it claims, must not resolve.
func TestJWKRejectsMismatchedParameters(t *testing.T) {
	for name, doc := range map[string]string{
		"EC with RSA members":             `{"kty":"EC","crv":"P-256","n":"AQAB","e":"AQAB"}`,
		"RSA with EC members":             `{"kty":"RSA","crv":"P-256","x":"AQAB","y":"AQAB"}`,
		"oct with EC members":             `{"kty":"oct","crv":"P-256","x":"AQAB","y":"AQAB"}`,
		"EC point off the curve":          `{"kty":"EC","crv":"P-256","x":"AQAB","y":"AQAB"}`,
		"EC on the wrong curve":           ecJWKOnWrongCurve(),
		"OKP with an EC curve":            `{"kty":"OKP","crv":"P-256","x":"AQAB"}`,
		"Ed25519 key of the wrong length": `{"kty":"OKP","crv":"Ed25519","x":"AQAB"}`,
		"unknown kty":                     `{"kty":"XYZ","x":"AQAB"}`,
		"missing kty":                     `{"x":"AQAB"}`,
		"empty oct":                       `{"kty":"oct","k":""}`,
		"RSA exponent of 1":               `{"kty":"RSA","n":"AQAB","e":"AQ"}`,
	} {
		if _, err := ParseJWK([]byte(doc)); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("%s: error = %v, want ErrInvalidKey", name, err)
		}
	}
}

// ecJWKOnWrongCurve builds a JWK whose point is a valid P-384 point but whose
// "crv" claims P-256.
func ecJWKOnWrongCurve() string {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		panic(err)
	}
	size := coordSize(elliptic.P384())
	return `{"kty":"EC","crv":"P-256","x":"` + EncodeSegment(padBig(k.X, size)) +
		`","y":"` + EncodeSegment(padBig(k.Y, size)) + `"}`
}

// ---------------------------------------------------------------------------
// ECDH-ES: invalid curve and degenerate points
// ---------------------------------------------------------------------------

// TestECDHRejectsInvalidEphemeralKey covers the invalid-curve attack: a sender
// who supplies an "epk" that is not a point on the recipient's curve can, in an
// implementation that skips the check, learn the recipient's private scalar one
// small subgroup at a time. crypto/ecdh validates on import; these cases check
// that no path around it exists.
func TestECDHRejectsInvalidEphemeralKey(t *testing.T) {
	recipient := testKeys.p256
	token, err := Encrypt([]byte("secret"), &recipient.PublicKey,
		EncryptOptions{Algorithm: ECDH_ES_A128KW, Encryption: A128GCM})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	header, err := decodeHeader(parts[0])
	if err != nil {
		t.Fatal(err)
	}

	curve := elliptic.P256()
	size := coordSize(curve)
	off, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]map[string]any{
		"point not on the curve": {
			"kty": "EC", "crv": "P-256",
			"x": EncodeSegment(padBig(big.NewInt(1), size)),
			"y": EncodeSegment(padBig(big.NewInt(1), size)),
		},
		"point at infinity": {
			"kty": "EC", "crv": "P-256",
			"x": EncodeSegment(make([]byte, size)),
			"y": EncodeSegment(make([]byte, size)),
		},
		"a valid point with its y coordinate negated off the curve": {
			"kty": "EC", "crv": "P-256",
			"x": EncodeSegment(padBig(recipient.X, size)),
			"y": EncodeSegment(padBig(new(big.Int).Add(recipient.Y, big.NewInt(1)), size)),
		},
		"epk on a curve the recipient does not use": {
			"kty": "EC", "crv": "P-384",
			"x": EncodeSegment(padBig(off.X, coordSize(elliptic.P384()))),
			"y": EncodeSegment(padBig(off.Y, coordSize(elliptic.P384()))),
		},
		"epk smuggling a private scalar": {
			"kty": "EC", "crv": "P-256",
			"x": EncodeSegment(padBig(recipient.X, size)),
			"y": EncodeSegment(padBig(recipient.Y, size)),
			"d": EncodeSegment(padBig(recipient.D, size)),
		},
	}
	for name, epk := range cases {
		tampered := copyHeader(header)
		tampered["epk"] = epk
		seg, err := encodeHeader(tampered)
		if err != nil {
			t.Fatal(err)
		}
		// The header is the AAD, so this will fail authentication regardless;
		// what matters is that the key agreement refuses first and never runs
		// ECDH against an unvalidated point.
		bad := strings.Join(append([]string{seg}, parts[1:]...), ".")
		if _, _, err := Decrypt(bad, recipient); err == nil {
			t.Errorf("%s: decryption succeeded", name)
		}
	}
	// Missing "epk" entirely.
	tampered := copyHeader(header)
	delete(tampered, "epk")
	seg, err := encodeHeader(tampered)
	if err != nil {
		t.Fatal(err)
	}
	bad := strings.Join(append([]string{seg}, parts[1:]...), ".")
	if _, _, err := Decrypt(bad, recipient); !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("missing epk: error = %v, want ErrInvalidHeader", err)
	}
}

// TestECDHDirectRejectsEncryptedKey checks RFC 7518 §4.6: direct key agreement
// transports no key, so a non-empty JWE Encrypted Key means the sender and
// recipient disagree about the algorithm.
func TestECDHDirectRejectsEncryptedKey(t *testing.T) {
	token, err := Encrypt([]byte("secret"), &testKeys.p256.PublicKey,
		EncryptOptions{Algorithm: ECDH_ES, Encryption: A128GCM})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if parts[1] != "" {
		t.Fatalf("ECDH-ES produced a non-empty encrypted key %q", parts[1])
	}
	parts[1] = EncodeSegment([]byte("smuggled"))
	if _, _, err := Decrypt(strings.Join(parts, "."), testKeys.p256); !errors.Is(err, ErrMalformed) {
		t.Errorf("error = %v, want ErrMalformed", err)
	}
}

// ---------------------------------------------------------------------------
// Content encryption: the tag gates the plaintext
// ---------------------------------------------------------------------------

// TestContentEncryptionAuthenticatesEverything mutates each authenticated field
// of a JWE in turn and requires a uniform failure. For the CBC-HMAC modes this
// is what keeps the composite from becoming a padding oracle; for GCM it is the
// AEAD contract. The AAD case matters most: the protected header is the AAD, so
// a header edit that decryption ignored would be a free rewrite of the token's
// metadata.
func TestContentEncryptionAuthenticatesEverything(t *testing.T) {
	for _, encName := range ContentEncryptionAlgorithms() {
		t.Run(encName, func(t *testing.T) {
			size, err := ContentEncryptionKeySize(encName)
			if err != nil {
				t.Fatal(err)
			}
			cek := make([]byte, size)
			if _, err := rand.Read(cek); err != nil {
				t.Fatal(err)
			}
			token, err := Encrypt([]byte("the plaintext"), cek,
				EncryptOptions{Algorithm: Dir, Encryption: encName, Header: map[string]any{"custom": "original"}})
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := Decrypt(token, cek); err != nil {
				t.Fatalf("baseline decrypt: %v", err)
			}
			parts := strings.Split(token, ".")

			// Rewrite an authenticated header parameter.
			header, err := decodeHeader(parts[0])
			if err != nil {
				t.Fatal(err)
			}
			header["custom"] = "rewritten"
			seg, err := encodeHeader(header)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := Decrypt(strings.Join(append([]string{seg}, parts[1:]...), "."), cek); !errors.Is(err, ErrDecryptFailed) {
				t.Errorf("rewritten AAD: error = %v, want ErrDecryptFailed", err)
			}

			// Flip one bit in the IV, the ciphertext, and the tag.
			for i, name := range map[int]string{2: "iv", 3: "ciphertext", 4: "tag"} {
				raw, err := DecodeSegment(parts[i])
				if err != nil {
					t.Fatal(err)
				}
				if len(raw) == 0 {
					continue
				}
				flipped := append([]byte(nil), raw...)
				flipped[0] ^= 0x01
				mutated := append([]string(nil), parts...)
				mutated[i] = EncodeSegment(flipped)
				if _, _, err := Decrypt(strings.Join(mutated, "."), cek); !errors.Is(err, ErrDecryptFailed) {
					t.Errorf("flipped %s: error = %v, want ErrDecryptFailed", name, err)
				}
				// Truncating a field must fail the same way, never degenerate
				// into an empty comparison that matches.
				mutated[i] = EncodeSegment(nil)
				if _, _, err := Decrypt(strings.Join(mutated, "."), cek); !errors.Is(err, ErrDecryptFailed) {
					t.Errorf("emptied %s: error = %v, want ErrDecryptFailed", name, err)
				}
			}
		})
	}
}

// TestCBCHMACTagCoversAADLength pins the AL field of RFC 7518 §5.2.2.1 to the
// AAD's length in *bits*. Getting this wrong (octets, or omitting AL) lets an
// attacker shift octets between the AAD and the ciphertext without disturbing
// the tag.
func TestCBCHMACTagCoversAADLength(t *testing.T) {
	ce := contentEncs[A128CBC_HS256]
	cek := make([]byte, ce.keySize)
	if _, err := rand.Read(cek); err != nil {
		t.Fatal(err)
	}
	iv, ct, tag, err := ce.encrypt(cek, []byte("plaintext"), []byte("headertail"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ce.decrypt(cek, iv, ct, tag, []byte("headertail")); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	// Same octets, different split: a length-agnostic tag would accept this.
	if _, err := ce.decrypt(cek, iv, ct, tag, []byte("header")); !errors.Is(err, ErrDecryptFailed) {
		t.Errorf("shortened AAD: error = %v, want ErrDecryptFailed", err)
	}
	if _, err := ce.decrypt(cek, iv, ct, tag, nil); !errors.Is(err, ErrDecryptFailed) {
		t.Errorf("removed AAD: error = %v, want ErrDecryptFailed", err)
	}
	// An empty tag must not pass as "nothing to check".
	if _, err := ce.decrypt(cek, iv, ct, nil, []byte("headertail")); !errors.Is(err, ErrDecryptFailed) {
		t.Errorf("empty tag: error = %v, want ErrDecryptFailed", err)
	}
	// A truncated tag must not pass either: comparing a prefix would halve the
	// forgery cost for every octet dropped.
	if _, err := ce.decrypt(cek, iv, ct, tag[:8], []byte("headertail")); !errors.Is(err, ErrDecryptFailed) {
		t.Errorf("truncated tag: error = %v, want ErrDecryptFailed", err)
	}
}

// TestRandomnessIsFreshPerMessage checks that the IV and the CEK come from
// crypto/rand rather than a fixed or counter-derived source. A repeated IV under
// the same key breaks GCM catastrophically — two messages leak their XOR and the
// authentication subkey — so this is worth asserting rather than assuming.
func TestRandomnessIsFreshPerMessage(t *testing.T) {
	const runs = 32
	for _, encName := range ContentEncryptionAlgorithms() {
		size, err := ContentEncryptionKeySize(encName)
		if err != nil {
			t.Fatal(err)
		}
		cek := make([]byte, size)
		if _, err := rand.Read(cek); err != nil {
			t.Fatal(err)
		}
		ivs := make(map[string]bool, runs)
		for i := 0; i < runs; i++ {
			token, err := Encrypt([]byte("same plaintext every time"), cek,
				EncryptOptions{Algorithm: Dir, Encryption: encName})
			if err != nil {
				t.Fatal(err)
			}
			iv := strings.Split(token, ".")[2]
			if ivs[iv] {
				t.Fatalf("%s: IV %q repeated within %d encryptions", encName, iv, runs)
			}
			ivs[iv] = true
		}
	}
	// The wrapped CEK must differ too, which it only can if the CEK is fresh.
	wrapped := make(map[string]bool, runs)
	for i := 0; i < runs; i++ {
		token, err := Encrypt([]byte("x"), testKeys.oct32,
			EncryptOptions{Algorithm: A256KW, Encryption: A256GCM})
		if err != nil {
			t.Fatal(err)
		}
		key := strings.Split(token, ".")[1]
		if wrapped[key] {
			t.Fatalf("wrapped CEK %q repeated within %d encryptions", key, runs)
		}
		wrapped[key] = true
	}
	// And so must the ECDH ephemeral key and the PBES2 salt.
	epks := make(map[string]bool, runs)
	salts := make(map[string]bool, runs)
	for i := 0; i < runs; i++ {
		token, err := Encrypt([]byte("x"), &testKeys.p256.PublicKey,
			EncryptOptions{Algorithm: ECDH_ES_A128KW, Encryption: A128GCM})
		if err != nil {
			t.Fatal(err)
		}
		h, err := decodeHeader(strings.Split(token, ".")[0])
		if err != nil {
			t.Fatal(err)
		}
		epk, _ := json.Marshal(h["epk"])
		if epks[string(epk)] {
			t.Fatalf("ephemeral key repeated within %d encryptions", runs)
		}
		epks[string(epk)] = true

		token, err = Encrypt([]byte("x"), []byte("correct horse battery staple"),
			EncryptOptions{Algorithm: PBES2_HS256_A128KW, Encryption: A128GCM,
				Header: map[string]any{"p2c": MinPBES2Count}})
		if err != nil {
			t.Fatal(err)
		}
		if h, err = decodeHeader(strings.Split(token, ".")[0]); err != nil {
			t.Fatal(err)
		}
		p2s, _ := h["p2s"].(string)
		if salts[p2s] {
			t.Fatalf("PBES2 salt %q repeated within %d encryptions", p2s, runs)
		}
		salts[p2s] = true
	}
}

// ---------------------------------------------------------------------------
// Attacker-controlled work
// ---------------------------------------------------------------------------

// TestPBES2CountIsBoundedBothWays checks the "p2c" header at both ends. A floor
// keeps a sender from handing over a password-derived key that is cheap to grind
// offline; a ceiling keeps a recipient from burning minutes of CPU on a header
// it has not authenticated yet. The huge-float case matters because Go leaves
// out-of-range float-to-int conversions implementation-defined.
func TestPBES2CountIsBoundedBothWays(t *testing.T) {
	password := []byte("correct horse battery staple")
	token, err := Encrypt([]byte("secret"), password,
		EncryptOptions{Algorithm: PBES2_HS256_A128KW, Encryption: A128GCM,
			Header: map[string]any{"p2c": MinPBES2Count}})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	header, err := decodeHeader(parts[0])
	if err != nil {
		t.Fatal(err)
	}

	for name, p2c := range map[string]any{
		"below the floor":  MinPBES2Count - 1,
		"zero":             0,
		"negative":         -1,
		"above the cap":    MaxPBES2Count + 1,
		"absurd":           1 << 40,
		"beyond float→int": 1e300,
		"fractional":       1.5,
		"a string":         "1000000000",
		"null":             nil,
	} {
		tampered := copyHeader(header)
		tampered["p2c"] = p2c
		seg, err := encodeHeader(tampered)
		if err != nil {
			t.Fatal(err)
		}
		bad := strings.Join(append([]string{seg}, parts[1:]...), ".")
		_, _, err = Decrypt(bad, password)
		if err == nil {
			t.Errorf("p2c %v (%s) was accepted", p2c, name)
			continue
		}
		if !errors.Is(err, ErrIterationCount) && !errors.Is(err, ErrInvalidHeader) {
			t.Errorf("p2c %v (%s): error = %v", p2c, name, err)
		}
	}

	// A missing or undersized salt is the same class of problem.
	for name, mutate := range map[string]func(map[string]any){
		"missing p2s": func(h map[string]any) { delete(h, "p2s") },
		"short p2s":   func(h map[string]any) { h["p2s"] = EncodeSegment([]byte("1234567")) },
		"huge p2s":    func(h map[string]any) { h["p2s"] = EncodeSegment(make([]byte, MaxPBES2SaltInput+1)) },
		"missing p2c": func(h map[string]any) { delete(h, "p2c") },
	} {
		tampered := copyHeader(header)
		mutate(tampered)
		seg, err := encodeHeader(tampered)
		if err != nil {
			t.Fatal(err)
		}
		bad := strings.Join(append([]string{seg}, parts[1:]...), ".")
		if _, _, err := Decrypt(bad, password); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// TestDecryptJSONRejectsUnprotectedZip covers the JWE analogue of the "b64"
// attack. "zip" decides how the authenticated plaintext is post-processed, so an
// unprotected copy would let an attacker turn a decrypted message into whatever
// its octets happen to inflate to — or, at minimum, into a decompression error
// that distinguishes plaintexts.
func TestDecryptJSONRejectsUnprotectedZip(t *testing.T) {
	key := testKeys.oct32
	doc, err := EncryptJSON([]byte("hello"), key,
		EncryptOptions{Algorithm: A256KW, Encryption: A256GCM})
	if err != nil {
		t.Fatal(err)
	}
	for _, where := range []string{"unprotected", "recipient"} {
		var m map[string]any
		if err := json.Unmarshal(doc, &m); err != nil {
			t.Fatal(err)
		}
		if where == "unprotected" {
			m["unprotected"] = map[string]any{"zip": "DEF"}
		} else {
			m["recipients"].([]any)[0].(map[string]any)["header"] = map[string]any{"zip": "DEF"}
		}
		tampered, _ := json.Marshal(m)
		if _, _, err := DecryptJSON(tampered, key); !errors.Is(err, ErrInvalidHeader) {
			t.Errorf("zip in the %s header: error = %v, want ErrInvalidHeader", where, err)
		}
	}
}

// TestDecryptRejectsUnknownZip makes sure an unrecognised compression algorithm
// is refused rather than ignored — ignoring it would return compressed octets as
// if they were the plaintext.
func TestDecryptRejectsUnknownZip(t *testing.T) {
	key := testKeys.oct32
	if _, err := Encrypt([]byte("x"), key, EncryptOptions{
		Algorithm: A256KW, Encryption: A256GCM,
		Header: map[string]any{"zip": "GZIP"},
	}); !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("Encrypt with zip=GZIP: error = %v, want ErrInvalidHeader", err)
	}
}

// TestAESKeyUnwrapRejectsShortInput checks the RFC 3394 integrity check against
// a truncated wrapper. The check compares an 8-octet initial value; an input too
// short to hold one must be rejected outright rather than compared against
// whatever happens to be there.
func TestAESKeyUnwrapRejectsShortInput(t *testing.T) {
	kek := testKeys.oct32
	wrapped, err := AESKeyWrap(kek, testKeys.oct32)
	if err != nil {
		t.Fatal(err)
	}
	for name, ct := range map[string][]byte{
		"nil":              nil,
		"empty":            {},
		"eight octets":     make([]byte, 8),
		"sixteen octets":   make([]byte, 16),
		"not a multiple":   make([]byte, 25),
		"truncated by one": wrapped[:len(wrapped)-8],
	} {
		if _, err := AESKeyUnwrap(kek, ct); err == nil {
			t.Errorf("AESKeyUnwrap accepted %s", name)
		}
	}
	// A flipped bit anywhere must fail the integrity check.
	for i := range wrapped {
		bad := append([]byte(nil), wrapped...)
		bad[i] ^= 0x80
		if _, err := AESKeyUnwrap(kek, bad); !errors.Is(err, ErrDecryptFailed) {
			t.Fatalf("flipped octet %d: error = %v, want ErrDecryptFailed", i, err)
		}
	}
}

// TestPBKDF2RejectsDegenerateInput guards the primitive itself: a zero or
// negative iteration count, or a zero-length output, must be an error rather
// than a silently empty key.
func TestPBKDF2RejectsDegenerateInput(t *testing.T) {
	for name, tc := range map[string]struct{ iter, keyLen int }{
		"zero iterations":     {0, 32},
		"negative iterations": {-1, 32},
		"zero key length":     {1000, 0},
		"negative key length": {1000, -1},
	} {
		if _, err := PBKDF2([]byte("pw"), []byte("saltsalt"), tc.iter, tc.keyLen, sha256.New); err == nil {
			t.Errorf("PBKDF2 accepted %s", name)
		}
	}
}

// TestDirRejectsEncryptedKey checks RFC 7518 §4.5: "dir" transports no key, so a
// non-empty JWE Encrypted Key is a protocol confusion and must be refused.
func TestDirRejectsEncryptedKey(t *testing.T) {
	token, err := Encrypt([]byte("secret"), testKeys.oct32,
		EncryptOptions{Algorithm: Dir, Encryption: A256GCM})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	parts[1] = EncodeSegment([]byte("smuggled"))
	if _, _, err := Decrypt(strings.Join(parts, "."), testKeys.oct32); !errors.Is(err, ErrMalformed) {
		t.Errorf("error = %v, want ErrMalformed", err)
	}
}
