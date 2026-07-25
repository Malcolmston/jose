package jose

import (
	"bytes"
	"compress/flate"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// testKeys holds one key of each kind, generated once for the whole package.
var testKeys = struct {
	rsa     *rsa.PrivateKey
	p256    *ecdsa.PrivateKey
	p384    *ecdsa.PrivateKey
	p521    *ecdsa.PrivateKey
	ed      ed25519.PrivateKey
	x25519  *ecdh.PrivateKey
	oct16   []byte
	oct24   []byte
	oct32   []byte
	oct48   []byte
	oct64   []byte
	initErr error
}{}

func init() {
	var err error
	if testKeys.rsa, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		testKeys.initErr = err
		return
	}
	if testKeys.p256, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		testKeys.initErr = err
		return
	}
	if testKeys.p384, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader); err != nil {
		testKeys.initErr = err
		return
	}
	if testKeys.p521, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader); err != nil {
		testKeys.initErr = err
		return
	}
	if _, testKeys.ed, err = ed25519.GenerateKey(rand.Reader); err != nil {
		testKeys.initErr = err
		return
	}
	if testKeys.x25519, err = ecdh.X25519().GenerateKey(rand.Reader); err != nil {
		testKeys.initErr = err
		return
	}
	for _, p := range []*[]byte{&testKeys.oct16, &testKeys.oct24, &testKeys.oct32, &testKeys.oct48, &testKeys.oct64} {
		_ = p
	}
	testKeys.oct16 = randBytes(16)
	testKeys.oct24 = randBytes(24)
	testKeys.oct32 = randBytes(32)
	testKeys.oct48 = randBytes(48)
	testKeys.oct64 = randBytes(64)
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func requireKeys(t *testing.T) {
	t.Helper()
	if testKeys.initErr != nil {
		t.Fatalf("test key generation failed: %v", testKeys.initErr)
	}
}

// octKeyFor returns a symmetric key of the size an "enc" algorithm needs.
func octKeyFor(t *testing.T, enc string) []byte {
	t.Helper()
	n, err := ContentEncryptionKeySize(enc)
	if err != nil {
		t.Fatal(err)
	}
	return randBytes(n)
}

// --- JWS round trips ---

func TestSignVerifyEveryAlgorithm(t *testing.T) {
	requireKeys(t)
	payload := []byte("the quick brown fox")

	for _, tc := range []struct {
		alg            string
		signKey, vfKey any
	}{
		{HS256, testKeys.oct32, testKeys.oct32},
		{HS384, testKeys.oct48, testKeys.oct48},
		{HS512, testKeys.oct64, testKeys.oct64},
		{RS256, testKeys.rsa, &testKeys.rsa.PublicKey},
		{RS384, testKeys.rsa, &testKeys.rsa.PublicKey},
		{RS512, testKeys.rsa, &testKeys.rsa.PublicKey},
		{PS256, testKeys.rsa, &testKeys.rsa.PublicKey},
		{PS384, testKeys.rsa, &testKeys.rsa.PublicKey},
		{PS512, testKeys.rsa, &testKeys.rsa.PublicKey},
		{ES256, testKeys.p256, &testKeys.p256.PublicKey},
		{ES384, testKeys.p384, &testKeys.p384.PublicKey},
		{ES512, testKeys.p521, &testKeys.p521.PublicKey},
		{EdDSA, testKeys.ed, testKeys.ed.Public()},
	} {
		t.Run(tc.alg, func(t *testing.T) {
			token, err := Sign(payload, tc.signKey, SignOptions{Algorithm: tc.alg, KeyID: "k1"})
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			got, header, err := Verify(token, tc.vfKey)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Errorf("payload = %q", got)
			}
			if Header(header).Algorithm() != tc.alg || Header(header).KeyID() != "k1" {
				t.Errorf("header = %v", header)
			}

			// The JSON serialization must carry the same guarantees.
			data, err := SignJSON(payload, tc.signKey, SignOptions{Algorithm: tc.alg, KeyID: "k1"})
			if err != nil {
				t.Fatalf("SignJSON: %v", err)
			}
			if got, _, err = VerifyJSON(data, tc.vfKey); err != nil {
				t.Fatalf("VerifyJSON: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Errorf("JSON payload = %q", got)
			}

			// A tampered signature must not verify.
			parts := strings.Split(token, ".")
			bad := parts[0] + "." + parts[1] + "." + flipLastChar(parts[2])
			if _, _, err := Verify(bad, tc.vfKey); err == nil {
				t.Error("a tampered signature verified")
			}
			// So must a tampered payload.
			bad = parts[0] + "." + EncodeSegment([]byte("other payload")) + "." + parts[2]
			if _, _, err := Verify(bad, tc.vfKey); !errors.Is(err, ErrSignatureInvalid) {
				t.Errorf("tampered payload: err = %v", err)
			}
		})
	}
}

// flipLastChar flips a bit in the octets a base64url segment decodes to and
// re-encodes it. Editing the encoded text directly is not enough: the final
// base64url character carries unused bits, so several spellings decode to the
// same octets.
func flipLastChar(s string) string {
	b, err := DecodeSegment(s)
	if err != nil || len(b) == 0 {
		return "AAAA"
	}
	b[0] ^= 0x80
	return EncodeSegment(b)
}

func TestSignDefaultAlgorithms(t *testing.T) {
	requireKeys(t)
	for _, tc := range []struct {
		key  any
		want string
	}{
		{testKeys.oct32, HS256},
		{testKeys.rsa, RS256},
		{testKeys.p256, ES256},
		{testKeys.p384, ES384},
		{testKeys.p521, ES512},
		{testKeys.ed, EdDSA},
	} {
		token, err := Sign([]byte("x"), tc.key, SignOptions{})
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		header, err := decodeHeader(strings.Split(token, ".")[0])
		if err != nil {
			t.Fatal(err)
		}
		if got := Header(header).Algorithm(); got != tc.want {
			t.Errorf("inferred alg = %q, want %q", got, tc.want)
		}
	}
}

// TestVerifyRejectsWrongKeyType is the algorithm-confusion guard: an HMAC
// verification must not accept an RSA public key, and vice versa.
func TestVerifyRejectsWrongKeyType(t *testing.T) {
	requireKeys(t)
	rsToken, err := Sign([]byte("x"), testKeys.rsa, SignOptions{Algorithm: RS256})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(rsToken, testKeys.oct32); !errors.Is(err, ErrInvalidKeyType) {
		t.Errorf("RS256 with a []byte key: err = %v, want ErrInvalidKeyType", err)
	}

	hsToken, err := Sign([]byte("x"), testKeys.oct32, SignOptions{Algorithm: HS256})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(hsToken, &testKeys.rsa.PublicKey); !errors.Is(err, ErrInvalidKeyType) {
		t.Errorf("HS256 with an RSA key: err = %v, want ErrInvalidKeyType", err)
	}

	// An ES256 signature must not verify with a P-384 key.
	esToken, err := Sign([]byte("x"), testKeys.p256, SignOptions{Algorithm: ES256})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(esToken, &testKeys.p384.PublicKey); !errors.Is(err, ErrInvalidKeyType) {
		t.Errorf("ES256 with a P-384 key: err = %v", err)
	}
}

// TestVerifyRejectsNone checks that the unsecured algorithm is refused, both
// when it is the declared alg and when an attacker strips a real signature.
func TestVerifyRejectsNone(t *testing.T) {
	requireKeys(t)
	header, err := encodeHeader(map[string]any{"alg": "none"})
	if err != nil {
		t.Fatal(err)
	}
	token := header + "." + EncodeSegment([]byte("payload")) + "."
	for _, key := range []any{testKeys.oct32, &testKeys.rsa.PublicKey, nil} {
		if _, _, err := Verify(token, key); !errors.Is(err, ErrNoneAlgDisallowed) {
			t.Errorf("Verify(none) with %T: err = %v, want ErrNoneAlgDisallowed", key, err)
		}
	}
	if _, err := Sign([]byte("x"), testKeys.oct32, SignOptions{Algorithm: "none"}); !errors.Is(err, ErrNoneAlgDisallowed) {
		t.Errorf("Sign(none): err = %v", err)
	}
	// The JSON serialization must refuse it too.
	doc := `{"payload":"cGF5bG9hZA","signatures":[{"protected":"` + header + `","signature":""}]}`
	if _, _, err := VerifyJSON([]byte(doc), testKeys.oct32); !errors.Is(err, ErrNoneAlgDisallowed) {
		t.Errorf("VerifyJSON(none): err = %v", err)
	}
}

// TestVerifyRejectsUnknownCrit covers RFC 7515 §4.1.11.
func TestVerifyRejectsUnknownCrit(t *testing.T) {
	requireKeys(t)
	token, err := Sign([]byte("x"), testKeys.oct32, SignOptions{
		Algorithm: HS256,
		Header:    map[string]any{"exp-ext": 1234},
		Critical:  []string{"exp-ext"},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, _, err := Verify(token, testKeys.oct32); !errors.Is(err, ErrInvalidCrit) {
		t.Errorf("unknown crit: err = %v, want ErrInvalidCrit", err)
	}
	// Declaring the extension makes it acceptable.
	if _, _, err := VerifyWithOptions(token, testKeys.oct32, VerifyOptions{
		KnownCritical: []string{"exp-ext"},
	}); err != nil {
		t.Errorf("declared crit: err = %v", err)
	}
}

// TestCritMalformed covers the ways a "crit" header can be invalid.
func TestCritMalformed(t *testing.T) {
	requireKeys(t)
	for name, header := range map[string]map[string]any{
		"not an array":        {"alg": HS256, "crit": "b64"},
		"empty array":         {"alg": HS256, "crit": []any{}},
		"non-string member":   {"alg": HS256, "crit": []any{1}},
		"registered name":     {"alg": HS256, "crit": []any{"kid"}, "kid": "k"},
		"parameter not there": {"alg": HS256, "crit": []any{"missing"}},
	} {
		protected, err := encodeHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		payload := EncodeSegment([]byte("x"))
		a, _ := lookupSigAlg(HS256)
		sig, err := a.sign(signingInput(protected, payload), testKeys.oct32)
		if err != nil {
			t.Fatal(err)
		}
		token := protected + "." + payload + "." + EncodeSegment(sig)
		if _, _, err := VerifyWithOptions(token, testKeys.oct32, VerifyOptions{
			KnownCritical: []string{"missing"},
		}); !errors.Is(err, ErrInvalidCrit) {
			t.Errorf("%s: err = %v, want ErrInvalidCrit", name, err)
		}
	}
}

func TestVerifyRestrictsAlgorithms(t *testing.T) {
	requireKeys(t)
	token, err := Sign([]byte("x"), testKeys.oct32, SignOptions{Algorithm: HS256})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyWithOptions(token, testKeys.oct32, VerifyOptions{
		Algorithms: []string{HS384, HS512},
	}); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("err = %v, want ErrSignatureInvalid", err)
	}
	if _, _, err := VerifyWithOptions(token, testKeys.oct32, VerifyOptions{
		Algorithms: []string{HS256},
	}); err != nil {
		t.Errorf("err = %v", err)
	}
}

func TestVerifyMalformed(t *testing.T) {
	requireKeys(t)
	for name, token := range map[string]string{
		"empty":          "",
		"two parts":      "aaa.bbb",
		"four parts":     "aaa.bbb.ccc.ddd",
		"header not b64": "!!!.bbb.ccc",
		"header not json": EncodeSegment([]byte("not json")) + "." +
			EncodeSegment([]byte("x")) + ".sig",
	} {
		if _, _, err := Verify(token, testKeys.oct32); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	// A header with no "alg" at all.
	protected, _ := encodeHeader(map[string]any{"typ": "JWT"})
	token := protected + "." + EncodeSegment([]byte("x")) + ".sig"
	if _, _, err := Verify(token, testKeys.oct32); !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("missing alg: err = %v", err)
	}
}

// TestSignDetachedAndUnencoded covers RFC 7515 Appendix F and RFC 7797.
func TestSignDetachedAndUnencoded(t *testing.T) {
	requireKeys(t)
	payload := []byte("detached content")

	token, err := Sign(payload, testKeys.oct32, SignOptions{
		Algorithm:     HS256,
		DetachPayload: true,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if strings.Split(token, ".")[1] != "" {
		t.Error("the payload was not detached")
	}
	if _, _, err := Verify(token, testKeys.oct32); !errors.Is(err, ErrDetachedPayload) {
		t.Errorf("err = %v, want ErrDetachedPayload", err)
	}
	got, _, err := VerifyWithOptions(token, testKeys.oct32, VerifyOptions{DetachedPayload: payload})
	if err != nil {
		t.Fatalf("VerifyWithOptions: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload = %q", got)
	}
	// A different payload must not verify.
	if _, _, err := VerifyWithOptions(token, testKeys.oct32, VerifyOptions{
		DetachedPayload: []byte("other content"),
	}); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("wrong detached payload: err = %v", err)
	}

	// RFC 7797 "b64":false.
	token, err = Sign(payload, testKeys.oct32, SignOptions{
		Algorithm: HS256,
		Header:    map[string]any{"b64": false},
		Critical:  []string{"b64"},
	})
	if err != nil {
		t.Fatalf("Sign (b64:false): %v", err)
	}
	if got := strings.Split(token, ".")[1]; got != string(payload) {
		t.Errorf("payload segment = %q, want the raw payload", got)
	}
	got, _, err = Verify(token, testKeys.oct32)
	if err != nil {
		t.Fatalf("Verify (b64:false): %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload = %q", got)
	}
	// "b64":false without "crit" is a specification violation.
	if _, err := Sign(payload, testKeys.oct32, SignOptions{
		Algorithm: HS256,
		Header:    map[string]any{"b64": false},
	}); !errors.Is(err, ErrInvalidCrit) {
		t.Errorf("b64 without crit: err = %v", err)
	}
	// An unencoded payload may not contain the separator.
	if _, err := Sign([]byte("a.b"), testKeys.oct32, SignOptions{
		Algorithm: HS256,
		Header:    map[string]any{"b64": false},
		Critical:  []string{"b64"},
	}); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("dot in an unencoded payload: err = %v", err)
	}
}

func TestSignCompactRejectsUnprotected(t *testing.T) {
	requireKeys(t)
	if _, err := Sign([]byte("x"), testKeys.oct32, SignOptions{
		Algorithm:   HS256,
		Unprotected: map[string]any{"kid": "k"},
	}); !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("err = %v, want ErrInvalidHeader", err)
	}
}

// --- JWE round trips ---

func TestEncryptDecryptEveryPair(t *testing.T) {
	requireKeys(t)
	plaintext := []byte("attack at dawn")

	type keyPair struct {
		alg            string
		encKey, decKey any
	}
	for _, enc := range ContentEncryptionAlgorithms() {
		octDir := octKeyFor(t, enc)
		for _, kp := range []keyPair{
			{RSA1_5, &testKeys.rsa.PublicKey, testKeys.rsa},
			{RSA_OAEP, &testKeys.rsa.PublicKey, testKeys.rsa},
			{RSA_OAEP_256, &testKeys.rsa.PublicKey, testKeys.rsa},
			{A128KW, testKeys.oct16, testKeys.oct16},
			{A192KW, testKeys.oct24, testKeys.oct24},
			{A256KW, testKeys.oct32, testKeys.oct32},
			{A128GCMKW, testKeys.oct16, testKeys.oct16},
			{A192GCMKW, testKeys.oct24, testKeys.oct24},
			{A256GCMKW, testKeys.oct32, testKeys.oct32},
			{Dir, octDir, octDir},
			{ECDH_ES, &testKeys.p256.PublicKey, testKeys.p256},
			{ECDH_ES_A128KW, &testKeys.p384.PublicKey, testKeys.p384},
			{ECDH_ES_A192KW, &testKeys.p521.PublicKey, testKeys.p521},
			{ECDH_ES_A256KW, testKeys.x25519.PublicKey(), testKeys.x25519},
		} {
			t.Run(kp.alg+"/"+enc, func(t *testing.T) {
				token, err := Encrypt(plaintext, kp.encKey, EncryptOptions{
					Algorithm:  kp.alg,
					Encryption: enc,
					KeyID:      "k1",
				})
				if err != nil {
					t.Fatalf("Encrypt: %v", err)
				}
				if n := len(strings.Split(token, ".")); n != 5 {
					t.Fatalf("compact JWE has %d parts", n)
				}
				got, header, err := Decrypt(token, kp.decKey)
				if err != nil {
					t.Fatalf("Decrypt: %v", err)
				}
				if !bytes.Equal(got, plaintext) {
					t.Errorf("plaintext = %q", got)
				}
				if Header(header).Algorithm() != kp.alg || Header(header).Encryption() != enc {
					t.Errorf("header = %v", header)
				}
				assertTamperingFails(t, token, kp.decKey)
			})
		}

		// PBES2 is exercised separately with a small iteration count so the
		// matrix stays fast.
		for _, alg := range []string{PBES2_HS256_A128KW, PBES2_HS384_A192KW, PBES2_HS512_A256KW} {
			t.Run(alg+"/"+enc, func(t *testing.T) {
				token, err := Encrypt(plaintext, []byte("correct horse battery staple"), EncryptOptions{
					Algorithm:  alg,
					Encryption: enc,
					Header:     map[string]any{"p2c": MinPBES2Count},
				})
				if err != nil {
					t.Fatalf("Encrypt: %v", err)
				}
				got, _, err := Decrypt(token, []byte("correct horse battery staple"))
				if err != nil {
					t.Fatalf("Decrypt: %v", err)
				}
				if !bytes.Equal(got, plaintext) {
					t.Errorf("plaintext = %q", got)
				}
				if _, _, err := Decrypt(token, []byte("wrong password")); !errors.Is(err, ErrDecryptFailed) {
					t.Errorf("wrong password: err = %v", err)
				}
			})
		}
	}
}

// assertTamperingFails flips a bit in each part of a compact JWE and requires
// that decryption fails, uniformly, with ErrDecryptFailed.
func assertTamperingFails(t *testing.T, token string, key any) {
	t.Helper()
	parts := strings.Split(token, ".")
	for i := range parts {
		if parts[i] == "" {
			continue
		}
		bad := append([]string(nil), parts...)
		bad[i] = flipLastChar(bad[i])
		if _, _, err := Decrypt(strings.Join(bad, "."), key); err == nil {
			t.Errorf("tampering with part %d did not fail", i)
		} else if i >= 1 && !errors.Is(err, ErrDecryptFailed) && !errors.Is(err, ErrMalformed) {
			t.Errorf("tampering with part %d: err = %v", i, err)
		}
	}
}

func TestDecryptWrongKey(t *testing.T) {
	requireKeys(t)
	token, err := Encrypt([]byte("secret"), testKeys.oct32, EncryptOptions{
		Algorithm:  A256KW,
		Encryption: A128CBC_HS256,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Decrypt(token, randBytes(32)); !errors.Is(err, ErrDecryptFailed) {
		t.Errorf("err = %v, want ErrDecryptFailed", err)
	}
	// A key of the wrong Go type must be rejected as such.
	if _, _, err := Decrypt(token, testKeys.rsa); !errors.Is(err, ErrInvalidKeyType) {
		t.Errorf("wrong key type: err = %v", err)
	}
}

func TestEncryptDefaults(t *testing.T) {
	requireKeys(t)
	token, err := Encrypt([]byte("x"), &testKeys.rsa.PublicKey, EncryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	header, err := decodeHeader(strings.Split(token, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	if Header(header).Algorithm() != RSA_OAEP_256 || Header(header).Encryption() != A256GCM {
		t.Errorf("defaults = %v", header)
	}
	if _, _, err := Decrypt(token, testKeys.rsa); err != nil {
		t.Errorf("Decrypt: %v", err)
	}
}

func TestEncryptUnsupported(t *testing.T) {
	requireKeys(t)
	if _, err := Encrypt(nil, testKeys.oct32, EncryptOptions{Algorithm: "A512KW"}); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("err = %v", err)
	}
	if _, err := Encrypt(nil, testKeys.oct32, EncryptOptions{Algorithm: A256KW, Encryption: "A512GCM"}); !errors.Is(err, ErrUnsupportedEncryption) {
		t.Errorf("err = %v", err)
	}
	if _, err := Encrypt(nil, testKeys.oct24, EncryptOptions{Algorithm: A256KW}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("wrong KEK size: err = %v", err)
	}
}

func TestDecryptRejectsUnknownCrit(t *testing.T) {
	requireKeys(t)
	token, err := Encrypt([]byte("x"), testKeys.oct32, EncryptOptions{
		Algorithm:  A256KW,
		Encryption: A128GCM,
		Header:     map[string]any{"crit": []string{"ext"}, "ext": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Decrypt(token, testKeys.oct32); !errors.Is(err, ErrInvalidCrit) {
		t.Errorf("err = %v, want ErrInvalidCrit", err)
	}
	if _, _, err := DecryptWithOptions(token, testKeys.oct32, DecryptOptions{
		KnownCritical: []string{"ext"},
	}); err != nil {
		t.Errorf("declared crit: err = %v", err)
	}
}

func TestDecryptRestrictsAlgorithms(t *testing.T) {
	requireKeys(t)
	token, err := Encrypt([]byte("x"), testKeys.oct32, EncryptOptions{
		Algorithm:  A256KW,
		Encryption: A128GCM,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := DecryptWithOptions(token, testKeys.oct32, DecryptOptions{
		Algorithms: []string{A128KW},
	}); !errors.Is(err, ErrDecryptFailed) {
		t.Errorf("alg filter: err = %v", err)
	}
	if _, _, err := DecryptWithOptions(token, testKeys.oct32, DecryptOptions{
		Encryptions: []string{A256GCM},
	}); !errors.Is(err, ErrDecryptFailed) {
		t.Errorf("enc filter: err = %v", err)
	}
}

// --- compression bomb ---

func TestCompressionRoundTrip(t *testing.T) {
	requireKeys(t)
	plaintext := bytes.Repeat([]byte("compress me "), 1000)
	token, err := Encrypt(plaintext, testKeys.oct32, EncryptOptions{
		Algorithm:  A256KW,
		Encryption: A128GCM,
		Compress:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Compression must actually have shrunk the ciphertext.
	if len(token) >= len(plaintext) {
		t.Errorf("compressed token is %d octets for a %d-octet payload", len(token), len(plaintext))
	}
	got, header, err := Decrypt(token, testKeys.oct32)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Error("compressed round trip lost data")
	}
	if got, _ := header["zip"].(string); got != "DEF" {
		t.Errorf("zip = %q", got)
	}
}

// TestDecompressionBomb builds a JWE whose DEFLATE payload expands enormously
// and requires that decryption refuses it rather than allocating.
func TestDecompressionBomb(t *testing.T) {
	requireKeys(t)
	// 64 MiB of zeros compresses to a few kilobytes.
	bomb := make([]byte, 64<<20)
	compressed, err := deflate(bomb)
	if err != nil {
		t.Fatal(err)
	}
	if len(compressed) > 1<<20 {
		t.Fatalf("the bomb did not compress: %d octets", len(compressed))
	}

	// Encrypt the *already compressed* octets with the "zip" header set, so
	// that decryption inflates them.
	enc, err := lookupEnc(A128GCM)
	if err != nil {
		t.Fatal(err)
	}
	header := map[string]any{"alg": Dir, "enc": A128GCM, "zip": "DEF"}
	protected, err := encodeHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	cek := octKeyFor(t, A128GCM)
	iv, ct, tag, err := enc.encrypt(cek, compressed, []byte(protected))
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Join([]string{protected, "", EncodeSegment(iv), EncodeSegment(ct), EncodeSegment(tag)}, ".")

	if _, _, err := Decrypt(token, cek); !errors.Is(err, ErrCompressionLimit) {
		t.Fatalf("err = %v, want ErrCompressionLimit", err)
	}
	// A tighter caller-supplied bound is honored too.
	if _, _, err := DecryptWithOptions(token, cek, DecryptOptions{MaxDecompressed: 1024}); !errors.Is(err, ErrCompressionLimit) {
		t.Errorf("custom bound: err = %v", err)
	}
	// And a payload that fits the bound still decrypts.
	if _, _, err := DecryptWithOptions(token, cek, DecryptOptions{MaxDecompressed: len(bomb)}); err != nil {
		t.Errorf("payload within the bound: err = %v", err)
	}
}

func TestInflateRejectsGarbage(t *testing.T) {
	if _, err := inflate([]byte{0xFF, 0xFF, 0xFF, 0xFF}, 1024); !errors.Is(err, ErrMalformed) {
		t.Errorf("err = %v, want ErrMalformed", err)
	}
	// A well-formed stream at exactly the limit is accepted.
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if out, err := inflate(buf.Bytes(), 100); err != nil || len(out) != 100 {
		t.Errorf("exact limit: %d octets, err = %v", len(out), err)
	}
	if _, err := inflate(buf.Bytes(), 99); !errors.Is(err, ErrCompressionLimit) {
		t.Errorf("one octet over: err = %v", err)
	}
}

// --- PBES2 iteration bound ---

func TestPBES2IterationBound(t *testing.T) {
	password := []byte("hunter2")
	// Forge a header asking for far more work than MaxPBES2Count allows and
	// check that we bail out before deriving anything.
	for _, p2c := range []int{MaxPBES2Count + 1, 1 << 30, MinPBES2Count - 1, 0, -1} {
		header := map[string]any{
			"alg": PBES2_HS256_A128KW,
			"enc": A128GCM,
			"p2s": EncodeSegment(randBytes(16)),
			"p2c": p2c,
		}
		protected, err := encodeHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		token := strings.Join([]string{
			protected,
			EncodeSegment(randBytes(24)),
			EncodeSegment(randBytes(12)),
			EncodeSegment(randBytes(16)),
			EncodeSegment(randBytes(16)),
		}, ".")
		if _, _, err := Decrypt(token, password); !errors.Is(err, ErrIterationCount) {
			t.Errorf("p2c=%d: err = %v, want ErrIterationCount", p2c, err)
		}
	}

	// The same bound applies when encrypting.
	if _, err := Encrypt(nil, password, EncryptOptions{
		Algorithm:  PBES2_HS256_A128KW,
		Encryption: A128GCM,
		Header:     map[string]any{"p2c": MaxPBES2Count + 1},
	}); !errors.Is(err, ErrIterationCount) {
		t.Errorf("Encrypt with an excessive p2c: err = %v", err)
	}

	// A missing or too-short salt is rejected as well.
	for name, hdr := range map[string]map[string]any{
		"no p2s":    {"alg": PBES2_HS256_A128KW, "enc": A128GCM, "p2c": MinPBES2Count},
		"short p2s": {"alg": PBES2_HS256_A128KW, "enc": A128GCM, "p2c": MinPBES2Count, "p2s": EncodeSegment([]byte("abc"))},
		"no p2c":    {"alg": PBES2_HS256_A128KW, "enc": A128GCM, "p2s": EncodeSegment(randBytes(16))},
	} {
		protected, err := encodeHeader(hdr)
		if err != nil {
			t.Fatal(err)
		}
		token := strings.Join([]string{protected, EncodeSegment(randBytes(24)),
			EncodeSegment(randBytes(12)), EncodeSegment(randBytes(16)), EncodeSegment(randBytes(16))}, ".")
		if _, _, err := Decrypt(token, password); !errors.Is(err, ErrInvalidHeader) {
			t.Errorf("%s: err = %v, want ErrInvalidHeader", name, err)
		}
	}
}

// --- JWK ---

func TestJWKRoundTrip(t *testing.T) {
	requireKeys(t)
	for _, key := range []any{
		testKeys.rsa, &testKeys.rsa.PublicKey,
		testKeys.p256, &testKeys.p256.PublicKey,
		testKeys.p384, testKeys.p521,
		testKeys.ed, testKeys.ed.Public(),
		testKeys.x25519, testKeys.x25519.PublicKey(),
		testKeys.oct32,
	} {
		jwk, err := FromKey(key)
		if err != nil {
			t.Fatalf("FromKey(%T): %v", key, err)
		}
		data, err := json.Marshal(jwk)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseJWK(data)
		if err != nil {
			t.Fatalf("ParseJWK(%T): %v", key, err)
		}
		if _, err := parsed.Key(); err != nil {
			t.Fatalf("Key(%T): %v", key, err)
		}
		thumb, err := parsed.Thumbprint()
		if err != nil {
			t.Fatalf("Thumbprint(%T): %v", key, err)
		}
		if thumb == "" {
			t.Errorf("empty thumbprint for %T", key)
		}
		if jwk.Kty != "oct" {
			pub, err := parsed.Public()
			if err != nil {
				t.Fatalf("Public(%T): %v", key, err)
			}
			pubThumb, err := pub.Thumbprint()
			if err != nil {
				t.Fatal(err)
			}
			// RFC 7638 thumbprints cover only public members, so the
			// private and public forms must agree.
			if pubThumb != thumb {
				t.Errorf("%T: public and private thumbprints differ", key)
			}
		}
	}
}

func TestJWKThumbprintRFC7638(t *testing.T) {
	// The worked example of RFC 7638 §3.1.
	const doc = `{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}`
	jwk, err := ParseJWK([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	got, err := jwk.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	const want = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	if got != want {
		t.Errorf("Thumbprint = %q, want %q", got, want)
	}
}

func TestJWKSet(t *testing.T) {
	requireKeys(t)
	a, err := FromKey(&testKeys.rsa.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	a.Kid = "a"
	b, err := FromKey(&testKeys.p256.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	b.Kid = "b"
	data, err := json.Marshal(JWKSet{Keys: []*JWK{a, b}})
	if err != nil {
		t.Fatal(err)
	}
	set, err := ParseJWKSet(data)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := set.LookupKeyID("b"); !ok || got.Kty != "EC" {
		t.Errorf("LookupKeyID(b) = %v, %v", got, ok)
	}
	if _, ok := set.LookupKeyID("missing"); ok {
		t.Error("LookupKeyID found a key that is not there")
	}
	// A set is usable directly as a verification key.
	token, err := Sign([]byte("x"), testKeys.p256, SignOptions{Algorithm: ES256, KeyID: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(token, set); err != nil {
		t.Errorf("Verify with a JWKSet: %v", err)
	}
	token, err = Sign([]byte("x"), testKeys.p256, SignOptions{Algorithm: ES256, KeyID: "zzz"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(token, set); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("unknown kid: err = %v", err)
	}
}

func TestJWKInvalid(t *testing.T) {
	for name, doc := range map[string]string{
		"empty":             `{}`,
		"unknown kty":       `{"kty":"XYZ"}`,
		"rsa missing n":     `{"kty":"RSA","e":"AQAB"}`,
		"bad base64":        `{"kty":"oct","k":"!!!!"}`,
		"unknown curve":     `{"kty":"EC","crv":"P-192","x":"AA","y":"AA"}`,
		"point off curve":   `{"kty":"EC","crv":"P-256","x":"AQ","y":"AQ"}`,
		"unknown okp crv":   `{"kty":"OKP","crv":"Ed448","x":"AA"}`,
		"short ed25519":     `{"kty":"OKP","crv":"Ed25519","x":"AA"}`,
		"not json":          `nope`,
		"rsa tiny exponent": `{"kty":"RSA","n":"AQAB","e":"AQ"}`,
	} {
		if _, err := ParseJWK([]byte(doc)); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("%s: err = %v, want ErrInvalidKey", name, err)
		}
	}
	if _, err := FromKey("a string"); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("FromKey(string): err = %v", err)
	}
	if _, err := (&JWK{Kty: "oct", K: "AAAA"}).Public(); !errors.Is(err, ErrInvalidKey) {
		t.Error("Public() on a symmetric key should fail")
	}
}

// --- registries ---

func TestAlgorithmRegistries(t *testing.T) {
	if got := len(SignatureAlgorithms()); got != 13 {
		t.Errorf("SignatureAlgorithms has %d entries, want 13", got)
	}
	if containsString(SignatureAlgorithms(), None) {
		t.Error("\"none\" must not be advertised as a signature algorithm")
	}
	if got := len(KeyManagementAlgorithms()); got != 17 {
		t.Errorf("KeyManagementAlgorithms has %d entries, want 17", got)
	}
	if got := len(ContentEncryptionAlgorithms()); got != 6 {
		t.Errorf("ContentEncryptionAlgorithms has %d entries, want 6", got)
	}
	for _, enc := range ContentEncryptionAlgorithms() {
		if _, err := ContentEncryptionKeySize(enc); err != nil {
			t.Errorf("ContentEncryptionKeySize(%s): %v", enc, err)
		}
	}
	if _, err := ContentEncryptionKeySize("nope"); !errors.Is(err, ErrUnsupportedEncryption) {
		t.Errorf("err = %v", err)
	}
}

func TestHeaderAccessors(t *testing.T) {
	h := Header{"alg": HS256, "enc": A128GCM, "kid": "k", "typ": "JWT", "cty": "text/plain"}
	if h.Algorithm() != HS256 || h.Encryption() != A128GCM || h.KeyID() != "k" ||
		h.Type() != "JWT" || h.ContentType() != "text/plain" {
		t.Errorf("accessors returned %v", h)
	}
	if h.String("missing") != "" {
		t.Error("String on a missing parameter should be empty")
	}
	if _, ok := h.Critical(); ok {
		t.Error("Critical should report absent")
	}
	h["crit"] = []any{"a", "b"}
	if got, ok := h.Critical(); !ok || len(got) != 2 {
		t.Errorf("Critical = %v, %v", got, ok)
	}
	h["crit"] = []any{1}
	if _, ok := h.Critical(); ok {
		t.Error("Critical should reject non-string members")
	}
}

func TestBase64Segments(t *testing.T) {
	if got := EncodeSegment([]byte{0xFB, 0xFF}); got != "-_8" {
		t.Errorf("EncodeSegment = %q", got)
	}
	if b, err := DecodeSegment("-_8"); err != nil || !bytes.Equal(b, []byte{0xFB, 0xFF}) {
		t.Errorf("DecodeSegment = %x, %v", b, err)
	}
	// Padded input is tolerated for robustness.
	if b, err := DecodeSegment("-_8="); err != nil || !bytes.Equal(b, []byte{0xFB, 0xFF}) {
		t.Errorf("padded DecodeSegment = %x, %v", b, err)
	}
	if _, err := DecodeSegment("!!!"); err == nil {
		t.Error("expected an error for invalid base64url")
	}
}
