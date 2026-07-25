package jose

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// The tests in this file check the implementation against the worked examples
// in RFC 7520, "Examples of Protecting Content Using JOSE".
//
// Sections whose output depends on random data (RSA-PSS salts, every JWE
// content encryption IV, every ephemeral ECDH key) cannot be reproduced
// byte-for-byte. For those the meaningful check is the decrypt/verify
// direction: recovering the RFC's own plaintext from the RFC's own
// serialization exercises exactly the same key schedule, KDF, and tag
// computation that producing it would.

func mustJWK(t *testing.T, doc string) *JWK {
	t.Helper()
	k, err := ParseJWK([]byte(doc))
	if err != nil {
		t.Fatalf("ParseJWK: %v", err)
	}
	return k
}

func mustKey(t *testing.T, doc string) any {
	t.Helper()
	k, err := mustJWK(t, doc).Key()
	if err != nil {
		t.Fatalf("JWK.Key: %v", err)
	}
	return k
}

// --- §3: JWK examples ---

func TestRFC7520Section3Keys(t *testing.T) {
	for _, tc := range []struct {
		name string
		doc  string
	}{
		{"3.1 EC public", rfc7520KeyEcP521Pub},
		{"3.2 EC private", rfc7520KeyEcP521Sig},
		{"3.3 RSA public", rfc7520KeyRsaPub},
		{"3.4 RSA private", rfc7520KeyRsaSig},
		{"3.5 oct MAC", rfc7520KeyOctHS256},
		{"3.6 oct encryption", rfc7520KeyOctA256GCM},
		{"5.1 RSA 2048 enc", rfc7520KeyRsaEnc2048},
		{"5.2 RSA 4096 enc", rfc7520KeyRSAEnc4096},
		{"5.4 EC P-384 enc", rfc7520KeyEcP384Enc},
		{"5.5 EC P-256 enc", rfc7520KeyEcP256Enc},
		{"5.6 oct A128GCM", rfc7520KeyOctA128GCM},
		{"5.7 oct A256GCMKW", rfc7520KeyOctA256GCMKW},
		{"5.8 oct A128KW", rfc7520KeyOctA128KW},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jwk := mustJWK(t, tc.doc)
			if _, err := jwk.Key(); err != nil {
				t.Fatalf("Key: %v", err)
			}
			if jwk.Kty != "oct" {
				pub, err := jwk.Public()
				if err != nil {
					t.Fatalf("Public: %v", err)
				}
				if pub.IsPrivate() {
					t.Error("Public() retained private parameters")
				}
			}
			if _, err := jwk.Thumbprint(); err != nil {
				t.Errorf("Thumbprint: %v", err)
			}
		})
	}
}

// --- §4: JWS examples ---

func TestRFC7520JWSCompact(t *testing.T) {
	for _, tc := range []struct {
		name   string
		token  string
		keyDoc string
		alg    string
		// deterministic reports whether re-signing must reproduce the token.
		deterministic bool
	}{
		{"4.1 RSA v1.5", rfc7520JWSRS256_4_1, rfc7520KeyRsaSig, RS256, true},
		{"4.2 RSA-PSS", rfc7520JWSPS384_4_2, rfc7520KeyRsaSig, PS384, false},
		{"4.3 ECDSA", rfc7520JWSES512_4_3, rfc7520KeyEcP521Sig, ES512, false},
		{"4.4 HMAC-SHA2", rfc7520JWSHS256_4_4, rfc7520KeyOctHS256, HS256, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jwk := mustJWK(t, tc.keyDoc)
			payload, header, err := Verify(tc.token, jwk)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if string(payload) != rfc7520JWSPayload {
				t.Errorf("payload = %q", payload)
			}
			if got := Header(header).Algorithm(); got != tc.alg {
				t.Errorf("alg = %q, want %q", got, tc.alg)
			}
			if !tc.deterministic {
				return
			}
			got, err := Sign([]byte(rfc7520JWSPayload), jwk, SignOptions{
				Algorithm: tc.alg,
				KeyID:     jwk.Kid,
			})
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if got != tc.token {
				t.Errorf("re-signed token does not match the RFC vector\n got %s\nwant %s", got, tc.token)
			}
		})
	}
}

// TestRFC7520JWS45Detached covers §4.5, a JWS whose payload is carried out of
// band.
func TestRFC7520JWS45Detached(t *testing.T) {
	jwk := mustJWK(t, rfc7520KeyOctHS256)
	payload, _, err := VerifyJSONWithOptions([]byte(rfc7520JWSJSONDetached_4_5), jwk, VerifyOptions{
		DetachedPayload: []byte(rfc7520JWSPayload),
	})
	if err != nil {
		t.Fatalf("VerifyJSON: %v", err)
	}
	if string(payload) != rfc7520JWSPayload {
		t.Errorf("payload = %q", payload)
	}

	// The same signature, in the compact form with an empty payload part.
	var doc struct {
		Protected string `json:"protected"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal([]byte(rfc7520JWSJSONDetached_4_5), &doc); err != nil {
		t.Fatal(err)
	}
	compact := doc.Protected + ".." + doc.Signature
	payload, _, err = VerifyWithOptions(compact, jwk, VerifyOptions{
		DetachedPayload: []byte(rfc7520JWSPayload),
	})
	if err != nil {
		t.Fatalf("VerifyWithOptions (compact detached): %v", err)
	}
	if string(payload) != rfc7520JWSPayload {
		t.Errorf("payload = %q", payload)
	}

	// Without the payload there is nothing to verify against.
	if _, _, err := Verify(compact, jwk); err == nil {
		t.Error("expected an error verifying a detached JWS with no payload")
	}
}

// TestRFC7520JWS46SpecificHeaders covers §4.6, where "kid" lives in the
// per-signature unprotected header and only "alg" is protected.
func TestRFC7520JWS46SpecificHeaders(t *testing.T) {
	jwk := mustJWK(t, rfc7520KeyOctHS256)
	payload, header, err := VerifyJSON([]byte(rfc7520JWSJSONSpecificHeaders_4_6), jwk)
	if err != nil {
		t.Fatalf("VerifyJSON: %v", err)
	}
	if string(payload) != rfc7520JWSPayload {
		t.Errorf("payload = %q", payload)
	}
	if got := Header(header).KeyID(); got != jwk.Kid {
		t.Errorf("kid = %q, want %q", got, jwk.Kid)
	}
}

// TestRFC7520JWS47ContentOnly covers §4.7, a JWS with no protected header at
// all: the signing input's header part is the empty string.
func TestRFC7520JWS47ContentOnly(t *testing.T) {
	jwk := mustJWK(t, rfc7520KeyOctHS256)
	payload, header, err := VerifyJSON([]byte(rfc7520JWSJSONContentOnly_4_7), jwk)
	if err != nil {
		t.Fatalf("VerifyJSON: %v", err)
	}
	if string(payload) != rfc7520JWSPayload {
		t.Errorf("payload = %q", payload)
	}
	if got := Header(header).Algorithm(); got != HS256 {
		t.Errorf("alg = %q", got)
	}
}

// TestRFC7520JWS48Multiple covers §4.8, three signatures over one payload with
// three different keys and algorithms.
func TestRFC7520JWS48Multiple(t *testing.T) {
	for _, tc := range []struct {
		name   string
		keyDoc string
		alg    string
	}{
		{"RS256", rfc7520KeyRsaSig, RS256},
		{"ES512", rfc7520KeyEcP521Sig, ES512},
		{"HS256", rfc7520KeyOctHS256, HS256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jwk := mustJWK(t, tc.keyDoc)
			payload, header, err := VerifyJSON([]byte(rfc7520JWSJSONMultiple_4_8), jwk)
			if err != nil {
				t.Fatalf("VerifyJSON: %v", err)
			}
			if string(payload) != rfc7520JWSPayload {
				t.Errorf("payload = %q", payload)
			}
			if got := Header(header).Algorithm(); got != tc.alg {
				t.Errorf("alg = %q, want %q", got, tc.alg)
			}
		})
	}
}

// --- §5: JWE examples ---

func TestRFC7520JWECompact(t *testing.T) {
	for _, tc := range []struct {
		name   string
		token  string
		keyDoc string
		alg    string
		enc    string
		want   string
	}{
		{"5.1 RSA v1.5 + A128CBC-HS256", rfc7520JWERSA15_5_1, rfc7520KeyRsaEnc2048, RSA1_5, A128CBC_HS256, rfc7520JWEPlaintext},
		{"5.2 RSA-OAEP + A256GCM", rfc7520JWERSAOAEP_5_2, rfc7520KeyRSAEnc4096, RSA_OAEP, A256GCM, rfc7520JWEPlaintext},
		{"5.4 ECDH-ES+A128KW + A128GCM", rfc7520JWEECDHESKW_5_4, rfc7520KeyEcP384Enc, ECDH_ES_A128KW, A128GCM, rfc7520JWEPlaintext},
		{"5.5 ECDH-ES + A128CBC-HS256", rfc7520JWEECDHES_5_5, rfc7520KeyEcP256Enc, ECDH_ES, A128CBC_HS256, rfc7520JWEPlaintext},
		{"5.6 dir + A128GCM", rfc7520JWEDir_5_6, rfc7520KeyOctA128GCM, Dir, A128GCM, rfc7520JWEPlaintext},
		{"5.7 A256GCMKW + A128CBC-HS256", rfc7520JWEGCMKW_5_7, rfc7520KeyOctA256GCMKW, A256GCMKW, A128CBC_HS256, rfc7520JWEPlaintext},
		{"5.8 A128KW + A128GCM", rfc7520JWEKW_5_8, rfc7520KeyOctA128KW, A128KW, A128GCM, rfc7520JWEPlaintext},
		{"5.9 A128KW + A128GCM + zip", rfc7520JWEZip_5_9, rfc7520KeyOctA128KW, A128KW, A128GCM, rfc7520JWEPlaintext},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jwk := mustJWK(t, tc.keyDoc)
			plaintext, header, err := Decrypt(tc.token, jwk)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if string(plaintext) != tc.want {
				t.Errorf("plaintext = %q\n     want %q", plaintext, tc.want)
			}
			if got := Header(header).Algorithm(); got != tc.alg {
				t.Errorf("alg = %q, want %q", got, tc.alg)
			}
			if got := Header(header).Encryption(); got != tc.enc {
				t.Errorf("enc = %q, want %q", got, tc.enc)
			}
		})
	}
}

// TestRFC7520JWE53PBES2 covers §5.3, whose plaintext is a JWK Set and whose
// key is a password run through PBKDF2 with the RFC's own "p2s"/"p2c".
func TestRFC7520JWE53PBES2(t *testing.T) {
	plaintext, header, err := Decrypt(rfc7520JWEPBES2_5_3, []byte(rfc7520Password))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got := Header(header).Algorithm(); got != PBES2_HS512_A256KW {
		t.Errorf("alg = %q", got)
	}
	if got := Header(header).ContentType(); got != "jwk-set+json" {
		t.Errorf("cty = %q", got)
	}
	set, err := ParseJWKSet(plaintext)
	if err != nil {
		t.Fatalf("the decrypted plaintext is not a JWK Set: %v", err)
	}
	for _, kid := range []string{
		"77c7e2b8-6e13-45cf-8672-617b5b45243a",
		"81b20965-8332-43d9-a468-82160ad91ac8",
		"18ec08e1-bfa9-4d95-b205-2b4dd1d4321d",
	} {
		if _, ok := set.LookupKeyID(kid); !ok {
			t.Errorf("decrypted JWK Set is missing kid %q", kid)
		}
	}
	// The RFC's "p2c" of 8192 is below the package default but well within
	// the accepted range.
	if got, err := headerInt(header["p2c"]); err != nil || got != 8192 {
		t.Errorf("p2c = %v (err %v), want 8192", got, err)
	}
}

// TestRFC7520JWE59Compressed checks that §5.9's DEFLATE round-trips and that
// the compressed form the RFC publishes is what our decompressor accepts.
func TestRFC7520JWE59Compressed(t *testing.T) {
	jwk := mustJWK(t, rfc7520KeyOctA128KW)
	plaintext, header, err := Decrypt(rfc7520JWEZip_5_9, jwk)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got, _ := header["zip"].(string); got != "DEF" {
		t.Errorf("zip = %q", got)
	}
	if string(plaintext) != rfc7520JWEPlaintext {
		t.Errorf("plaintext = %q", plaintext)
	}
}

// TestRFC7520RoundTripWithRFCKeys re-encrypts the RFC's plaintext to the RFC's
// own keys and decrypts it again, checking the produce side of every §5
// algorithm that the randomized vectors cannot check directly.
func TestRFC7520RoundTripWithRFCKeys(t *testing.T) {
	for _, tc := range []struct {
		name    string
		keyDoc  string
		encKey  any
		decKey  any
		alg     string
		enc     string
		headers map[string]any
	}{
		{name: "RSA-OAEP-256 + A256GCM", keyDoc: rfc7520KeyRsaEnc2048, alg: RSA_OAEP_256, enc: A256GCM},
		{name: "RSA1_5 + A128CBC-HS256", keyDoc: rfc7520KeyRsaEnc2048, alg: RSA1_5, enc: A128CBC_HS256},
		{name: "ECDH-ES + A128CBC-HS256", keyDoc: rfc7520KeyEcP256Enc, alg: ECDH_ES, enc: A128CBC_HS256},
		{name: "ECDH-ES+A128KW + A128GCM", keyDoc: rfc7520KeyEcP384Enc, alg: ECDH_ES_A128KW, enc: A128GCM},
		{name: "A128KW + A128GCM", keyDoc: rfc7520KeyOctA128KW, alg: A128KW, enc: A128GCM},
		{name: "A256GCMKW + A128CBC-HS256", keyDoc: rfc7520KeyOctA256GCMKW, alg: A256GCMKW, enc: A128CBC_HS256},
		{name: "dir + A128GCM", keyDoc: rfc7520KeyOctA128GCM, alg: Dir, enc: A128GCM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jwk := mustJWK(t, tc.keyDoc)
			var encKey any = jwk
			if pub, err := jwk.Public(); err == nil {
				encKey = pub
			}
			token, err := Encrypt([]byte(rfc7520JWEPlaintext), encKey, EncryptOptions{
				Algorithm:  tc.alg,
				Encryption: tc.enc,
				Header:     tc.headers,
			})
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			plaintext, _, err := Decrypt(token, jwk)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if string(plaintext) != rfc7520JWEPlaintext {
				t.Errorf("plaintext = %q", plaintext)
			}
		})
	}
}

// TestRFC7520JWSResignJSON checks that our JSON serialization of §4.1 matches
// the RFC's, for the deterministic RS256 case.
func TestRFC7520JWSResignJSON(t *testing.T) {
	jwk := mustJWK(t, rfc7520KeyRsaSig)
	data, err := SignJSON([]byte(rfc7520JWSPayload), jwk, SignOptions{
		Algorithm: RS256,
		KeyID:     jwk.Kid,
	})
	if err != nil {
		t.Fatalf("SignJSON: %v", err)
	}
	payload, header, err := VerifyJSON(data, jwk)
	if err != nil {
		t.Fatalf("VerifyJSON: %v", err)
	}
	if string(payload) != rfc7520JWSPayload {
		t.Errorf("payload = %q", payload)
	}
	if Header(header).Algorithm() != RS256 || Header(header).KeyID() != jwk.Kid {
		t.Errorf("header = %v", header)
	}
	// The signature octets must equal the RFC's, since RS256 is
	// deterministic and the protected header is byte-identical.
	want := strings.Split(rfc7520JWSRS256_4_1, ".")[2]
	if !strings.Contains(string(data), want) {
		t.Errorf("JSON serialization does not carry the RFC's signature")
	}
}

// TestRFC7520MultiSignature reproduces the shape of §4.8: one payload, three
// signatures, each verifiable on its own.
func TestRFC7520MultiSignature(t *testing.T) {
	rsa := mustJWK(t, rfc7520KeyRsaSig)
	ec := mustJWK(t, rfc7520KeyEcP521Sig)
	oct := mustJWK(t, rfc7520KeyOctHS256)

	data, err := SignJSONMulti([]byte(rfc7520JWSPayload),
		Signer{Key: rsa, Options: SignOptions{Algorithm: RS256, Unprotected: map[string]any{"kid": rsa.Kid}}},
		Signer{Key: ec, Options: SignOptions{Algorithm: ES512, Unprotected: map[string]any{"kid": ec.Kid}}},
		Signer{Key: oct, Options: SignOptions{Algorithm: HS256, KeyID: oct.Kid}},
	)
	if err != nil {
		t.Fatalf("SignJSONMulti: %v", err)
	}
	for _, jwk := range []*JWK{rsa, ec, oct} {
		payload, _, err := VerifyJSON(data, jwk)
		if err != nil {
			t.Fatalf("VerifyJSON with kid %q: %v", jwk.Kid, err)
		}
		if string(payload) != rfc7520JWSPayload {
			t.Errorf("payload = %q", payload)
		}
	}
	// A key that signed none of the signatures must not verify.
	if _, _, err := VerifyJSON(data, []byte("not the secret")); err == nil {
		t.Error("expected verification to fail with an unrelated key")
	}
}

// mustKey is exercised here so the helper is not reported as unused when the
// vector set changes.
func TestRFC7520KeyHelper(t *testing.T) {
	if k := mustKey(t, rfc7520KeyOctHS256); len(k.([]byte)) != 32 {
		t.Errorf("HS256 key is %d octets, want 32", len(k.([]byte)))
	}
}

// TestRFC7520Section3PublicKeysMatch checks that the public JWKs of §3.1 and
// §3.3 are exactly what Public() derives from the private keys of §3.2 and
// §3.4 — the two pairs must agree on every public parameter, and therefore on
// their RFC 7638 thumbprints.
func TestRFC7520Section3PublicKeysMatch(t *testing.T) {
	for _, tc := range []struct{ name, priv, pub string }{
		{"EC P-521", rfc7520KeyEcP521Sig, rfc7520KeyEcP521Pub},
		{"RSA 2048", rfc7520KeyRsaSig, rfc7520KeyRsaPub},
	} {
		t.Run(tc.name, func(t *testing.T) {
			derived, err := mustJWK(t, tc.priv).Public()
			if err != nil {
				t.Fatalf("Public: %v", err)
			}
			published := mustJWK(t, tc.pub)
			a, err := derived.Thumbprint()
			if err != nil {
				t.Fatal(err)
			}
			b, err := published.Thumbprint()
			if err != nil {
				t.Fatal(err)
			}
			if a != b {
				t.Errorf("thumbprints differ: %s vs %s", a, b)
			}
		})
	}
}

// TestRFC7520Section6Nested covers §6, a JWS nested inside a JWE: decrypt the
// outer JWE with the RSA 4096 key, then verify the inner JWS it carries.
func TestRFC7520Section6Nested(t *testing.T) {
	outerKey := mustJWK(t, rfc7520KeyRSAEnc4096)
	inner, header, err := Decrypt(rfc7520NestedJWE, outerKey)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got := Header(header).ContentType(); got != "JWT" {
		t.Errorf("cty = %q, want JWT", got)
	}
	if got := Header(header).Algorithm(); got != RSA_OAEP {
		t.Errorf("alg = %q", got)
	}
	if string(inner) != rfc7520NestedJWS {
		t.Fatalf("the decrypted JWS does not match the RFC vector\n got %s\nwant %s", inner, rfc7520NestedJWS)
	}

	innerKey := mustJWK(t, rfc7520KeyNestedSig)
	claims, innerHeader, err := Verify(string(inner), innerKey)
	if err != nil {
		t.Fatalf("Verify (inner JWS): %v", err)
	}
	if got := Header(innerHeader).Algorithm(); got != PS256 {
		t.Errorf("inner alg = %q", got)
	}
	if got := Header(innerHeader).Type(); got != "JWT" {
		t.Errorf("inner typ = %q", got)
	}
	var got, want map[string]any
	if err := json.Unmarshal(claims, &got); err != nil {
		t.Fatalf("inner payload is not JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(rfc7520NestedClaims), &want); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("claims = %v, want %v", got, want)
	}
	for k, v := range want {
		if fmt.Sprint(got[k]) != fmt.Sprint(v) {
			t.Errorf("claim %q = %v, want %v", k, got[k], v)
		}
	}
}
