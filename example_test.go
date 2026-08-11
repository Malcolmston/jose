package jose_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/malcolmston/jose"
)

// ExampleSign shows the compact JWS most callers want: sign with a shared
// secret, then verify with the expected algorithm pinned. Pinning "alg" is the
// single most important thing a verifier does — without it, the token's own
// header chooses the algorithm.
func ExampleSign() {
	secret := []byte("a 32-octet secret for HMAC-SHA256")

	token, err := jose.Sign([]byte(`{"sub":"alice"}`), secret,
		jose.SignOptions{Algorithm: jose.HS256})
	if err != nil {
		panic(err)
	}

	payload, header, err := jose.VerifyWithOptions(token, secret,
		jose.VerifyOptions{Algorithms: []string{jose.HS256}})
	if err != nil {
		panic(err)
	}
	fmt.Printf("alg=%s payload=%s\n", jose.Header(header).Algorithm(), payload)
	// Output: alg=HS256 payload={"sub":"alice"}
}

// ExampleVerifyWithOptions demonstrates the defence against algorithm
// confusion. An attacker who has the RSA *public* key can MAC a token with it
// and claim "alg":"HS256"; a verifier that trusted the header would recompute
// the same MAC and accept. Here the HMAC algorithm type-asserts its key, so an
// *rsa.PublicKey never reaches it.
func ExampleVerifyWithOptions_algorithmConfusion() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// The attacker MACs with material derived from the public key.
	forged, err := jose.Sign([]byte(`{"admin":true}`), []byte("public key bytes"),
		jose.SignOptions{Algorithm: jose.HS256})
	if err != nil {
		panic(err)
	}

	_, _, err = jose.Verify(forged, &key.PublicKey)
	fmt.Println(errors.Is(err, jose.ErrInvalidKeyType))
	// Output: true
}

// ExampleVerify_none shows that the unsecured "none" algorithm is refused
// unconditionally. There is no option to enable it.
func ExampleVerify_none() {
	// header {"alg":"none"}, payload {"admin":true}, empty signature
	token := "eyJhbGciOiJub25lIn0.eyJhZG1pbiI6dHJ1ZX0."

	_, _, err := jose.Verify(token, []byte("irrelevant"))
	fmt.Println(errors.Is(err, jose.ErrNoneAlgDisallowed))
	// Output: true
}

// ExampleSign_detached produces a JWS whose payload travels out of band
// (RFC 7515 Appendix F). The payload is still covered by the signature, so the
// verifier must supply the identical octets.
func ExampleSign_detached() {
	secret := []byte("a 32-octet secret for HMAC-SHA256")
	payload := []byte("a large document that is stored elsewhere")

	token, err := jose.Sign(payload, secret,
		jose.SignOptions{Algorithm: jose.HS256, DetachPayload: true})
	if err != nil {
		panic(err)
	}

	got, _, err := jose.VerifyWithOptions(token, secret,
		jose.VerifyOptions{Algorithms: []string{jose.HS256}, DetachedPayload: payload})
	if err != nil {
		panic(err)
	}
	fmt.Println(string(got))

	// A different payload does not verify, which is the point.
	_, _, err = jose.VerifyWithOptions(token, secret,
		jose.VerifyOptions{Algorithms: []string{jose.HS256}, DetachedPayload: []byte("a different document")})
	fmt.Println(errors.Is(err, jose.ErrSignatureInvalid))
	// Output:
	// a large document that is stored elsewhere
	// true
}

// ExampleSignJSONMulti signs one payload with two keys and serializes both
// signatures in a single general JSON document (RFC 7515 §7.2.1). Each
// recipient verifies with the key it holds; neither signature vouches for the
// other.
func ExampleSignJSONMulti() {
	secret := []byte("a 32-octet secret for HMAC-SHA256")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	doc, err := jose.SignJSONMulti([]byte("shared payload"),
		jose.Signer{Key: secret, Options: jose.SignOptions{Algorithm: jose.HS256}},
		jose.Signer{Key: ecKey, Options: jose.SignOptions{Algorithm: jose.ES256}},
	)
	if err != nil {
		panic(err)
	}

	for _, key := range []any{secret, &ecKey.PublicKey} {
		payload, header, err := jose.VerifyJSON(doc, key)
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s verified %q\n", jose.Header(header).Algorithm(), payload)
	}
	// Output:
	// HS256 verified "shared payload"
	// ES256 verified "shared payload"
}

// ExampleEncrypt produces a compact JWE. "dir" uses the supplied key as the
// content encryption key directly, so nothing is transmitted in the JWE
// Encrypted Key.
func ExampleEncrypt() {
	cek := make([]byte, 32) // A256GCM takes a 32-octet key
	if _, err := rand.Read(cek); err != nil {
		panic(err)
	}

	token, err := jose.Encrypt([]byte("attack at dawn"), cek,
		jose.EncryptOptions{Algorithm: jose.Dir, Encryption: jose.A256GCM})
	if err != nil {
		panic(err)
	}

	plaintext, header, err := jose.DecryptWithOptions(token, cek,
		jose.DecryptOptions{
			Algorithms:  []string{jose.Dir},
			Encryptions: []string{jose.A256GCM},
		})
	if err != nil {
		panic(err)
	}
	fmt.Printf("enc=%s plaintext=%s\n", jose.Header(header).Encryption(), plaintext)
	// Output: enc=A256GCM plaintext=attack at dawn
}

// ExampleEncrypt_ecdh encrypts to an EC public key with ephemeral-static
// Diffie-Hellman. The sender needs only the recipient's public key; the
// ephemeral public key travels in the "epk" header.
func ExampleEncrypt_ecdh() {
	recipient, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	token, err := jose.Encrypt([]byte("for your eyes only"), &recipient.PublicKey,
		jose.EncryptOptions{Algorithm: jose.ECDH_ES_A256KW, Encryption: jose.A256GCM})
	if err != nil {
		panic(err)
	}

	plaintext, _, err := jose.Decrypt(token, recipient)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(plaintext))
	// Output: for your eyes only
}

// ExampleEncryptJSONMulti encrypts once and delivers the content encryption key
// to two recipients under different key management algorithms — something the
// compact serialization cannot express.
func ExampleEncryptJSONMulti() {
	alice := make([]byte, 32)
	if _, err := rand.Read(alice); err != nil {
		panic(err)
	}
	bob, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	doc, err := jose.EncryptJSONMulti([]byte("one message, two readers"),
		jose.EncryptOptions{Encryption: jose.A256GCM},
		jose.Recipient{Key: alice, Algorithm: jose.A256KW, KeyID: "alice"},
		jose.Recipient{Key: &bob.PublicKey, Algorithm: jose.ECDH_ES_A256KW, KeyID: "bob"},
	)
	if err != nil {
		panic(err)
	}

	for _, key := range []any{alice, bob} {
		plaintext, header, err := jose.DecryptJSON(doc, key)
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s: %s\n", jose.Header(header).KeyID(), plaintext)
	}
	// Output:
	// alice: one message, two readers
	// bob: one message, two readers
}

// ExampleEncrypt_password derives the key-wrapping key from a password with
// PBES2. The iteration count travels in the "p2c" header, and because that
// header is attacker-controlled the decrypter bounds it at both ends before
// doing any work.
func ExampleEncrypt_password() {
	password := []byte("correct horse battery staple")

	token, err := jose.Encrypt([]byte("secret note"), password,
		jose.EncryptOptions{
			Algorithm:  jose.PBES2_HS256_A128KW,
			Encryption: jose.A128GCM,
			Header:     map[string]any{"p2c": jose.MinPBES2Count},
		})
	if err != nil {
		panic(err)
	}

	plaintext, header, err := jose.Decrypt(token, password)
	if err != nil {
		panic(err)
	}
	fmt.Printf("p2c=%v plaintext=%s\n", header["p2c"], plaintext)
	// Output: p2c=1000 plaintext=secret note
}

// ExampleFromKey converts a Go key to a JWK, strips it to its public half for
// publication, and derives the RFC 7638 thumbprint that conventionally serves as
// the "kid".
func ExampleFromKey() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	private, err := jose.FromKey(key)
	if err != nil {
		panic(err)
	}
	public, err := private.Public()
	if err != nil {
		panic(err)
	}

	thumb, err := public.Thumbprint()
	if err != nil {
		panic(err)
	}
	fmt.Printf("kty=%s crv=%s private=%v public-has-d=%v thumbprint-length=%d\n",
		public.Kty, public.Crv, private.IsPrivate(), public.IsPrivate(), len(thumb))
	// Output: kty=EC crv=P-256 private=true public-has-d=false thumbprint-length=43
}

// ExampleParseJWKSet resolves a key from a JWK Set by the "kid" the token
// names, which is how a verifier follows a provider's key rotation.
func ExampleParseJWKSet() {
	const jwks = `{"keys":[
		{"kty":"oct","kid":"2023","use":"sig","alg":"HS256","k":"c2VjcmV0LWZyb20tMjAyMy1zaWduaW5nLWtleQ"},
		{"kty":"oct","kid":"2024","use":"sig","alg":"HS256","k":"c2VjcmV0LWZyb20tMjAyNC1zaWduaW5nLWtleQ"}
	]}`

	set, err := jose.ParseJWKSet([]byte(jwks))
	if err != nil {
		panic(err)
	}
	current, ok := set.LookupKeyID("2024")
	if !ok {
		panic("kid 2024 not found")
	}

	token, err := jose.Sign([]byte("payload"), current,
		jose.SignOptions{Algorithm: jose.HS256, KeyID: "2024"})
	if err != nil {
		panic(err)
	}

	// The verifier hands over the whole set; the "kid" header selects the key.
	payload, header, err := jose.VerifyWithOptions(token, set,
		jose.VerifyOptions{Algorithms: []string{jose.HS256}})
	if err != nil {
		panic(err)
	}
	fmt.Printf("kid=%s payload=%s\n", jose.Header(header).KeyID(), payload)
	// Output: kid=2024 payload=payload
}

// ExampleJWK_Public shows that a JWK published for verification carries no
// private material, and that a symmetric key correctly reports it has no public
// form rather than handing back the secret.
func ExampleJWK_Public() {
	oct, err := jose.FromKey([]byte("a symmetric secret"))
	if err != nil {
		panic(err)
	}
	_, err = oct.Public()
	fmt.Println(errors.Is(err, jose.ErrInvalidKey))
	// Output: true
}

// ExampleDecryptWithOptions_compressionBomb shows the bound on "zip":"DEF".
// DEFLATE reaches ratios well past 1000:1, so an unbounded inflate turns a small
// token into a memory-exhaustion attack.
func ExampleDecryptWithOptions_compressionBomb() {
	cek := make([]byte, 32)
	if _, err := rand.Read(cek); err != nil {
		panic(err)
	}
	// A megabyte of zeros compresses to about a kilobyte.
	token, err := jose.Encrypt(make([]byte, 1<<20), cek,
		jose.EncryptOptions{Algorithm: jose.Dir, Encryption: jose.A256GCM, Compress: true})
	if err != nil {
		panic(err)
	}

	_, _, err = jose.DecryptWithOptions(token, cek,
		jose.DecryptOptions{MaxDecompressed: 4096})
	fmt.Println(errors.Is(err, jose.ErrCompressionLimit))

	_, _, err = jose.Decrypt(token, cek) // the 16 MiB default
	fmt.Println(err)
	// Output:
	// true
	// <nil>
}

// ExampleSignatureAlgorithms lists the registries this package implements.
// "none" is deliberately absent from the signature list.
func ExampleSignatureAlgorithms() {
	fmt.Println(jose.SignatureAlgorithms())
	fmt.Println(jose.ContentEncryptionAlgorithms())
	// Output:
	// [ES256 ES384 ES512 EdDSA HS256 HS384 HS512 PS256 PS384 PS512 RS256 RS384 RS512]
	// [A128CBC-HS256 A128GCM A192CBC-HS384 A192GCM A256CBC-HS512 A256GCM]
}
