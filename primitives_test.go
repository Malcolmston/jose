package jose

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// --- AES Key Wrap (RFC 3394) ---

// TestAESKeyWrapRFC3394 runs the six test vectors of RFC 3394 §4.
func TestAESKeyWrapRFC3394(t *testing.T) {
	for _, tc := range []struct {
		name    string
		kek     string
		key     string
		wrapped string
	}{
		{
			"4.1 128-bit data, 128-bit KEK",
			"000102030405060708090A0B0C0D0E0F",
			"00112233445566778899AABBCCDDEEFF",
			"1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
		},
		{
			"4.2 128-bit data, 192-bit KEK",
			"000102030405060708090A0B0C0D0E0F1011121314151617",
			"00112233445566778899AABBCCDDEEFF",
			"96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
		},
		{
			"4.3 128-bit data, 256-bit KEK",
			"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			"00112233445566778899AABBCCDDEEFF",
			"64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
		},
		{
			"4.4 192-bit data, 192-bit KEK",
			"000102030405060708090A0B0C0D0E0F1011121314151617",
			"00112233445566778899AABBCCDDEEFF0001020304050607",
			"031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2",
		},
		{
			"4.5 192-bit data, 256-bit KEK",
			"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			"00112233445566778899AABBCCDDEEFF0001020304050607",
			"A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
		},
		{
			"4.6 256-bit data, 256-bit KEK",
			"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			"00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
			"28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kek := mustHex(t, tc.kek)
			key := mustHex(t, tc.key)
			want := mustHex(t, tc.wrapped)

			got, err := AESKeyWrap(kek, key)
			if err != nil {
				t.Fatalf("AESKeyWrap: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("wrapped = %X, want %X", got, want)
			}
			back, err := AESKeyUnwrap(kek, want)
			if err != nil {
				t.Fatalf("AESKeyUnwrap: %v", err)
			}
			if !bytes.Equal(back, key) {
				t.Errorf("unwrapped = %X, want %X", back, key)
			}
		})
	}
}

// TestAESKeyUnwrapRejectsTamper checks the RFC 3394 integrity value.
func TestAESKeyUnwrapRejectsTamper(t *testing.T) {
	kek := mustHex(t, "000102030405060708090A0B0C0D0E0F")
	wrapped := mustHex(t, "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
	for i := range wrapped {
		bad := bytes.Clone(wrapped)
		bad[i] ^= 0x01
		if _, err := AESKeyUnwrap(kek, bad); !errors.Is(err, ErrDecryptFailed) {
			t.Fatalf("flipping octet %d: err = %v, want ErrDecryptFailed", i, err)
		}
	}
	if _, err := AESKeyUnwrap(kek, wrapped[:16]); err == nil {
		t.Error("expected an error for a short ciphertext")
	}
	if _, err := AESKeyWrap(kek, make([]byte, 8)); err == nil {
		t.Error("expected an error wrapping fewer than 16 octets")
	}
	if _, err := AESKeyWrap(kek, make([]byte, 20)); err == nil {
		t.Error("expected an error wrapping a non-multiple of 8")
	}
}

// --- PBKDF2 (RFC 8018) ---

// TestPBKDF2RFC6070 runs the PBKDF2-HMAC-SHA-1 vectors of RFC 6070.
func TestPBKDF2RFC6070(t *testing.T) {
	for _, tc := range []struct {
		password, salt string
		iter, dkLen    int
		want           string
	}{
		{"password", "salt", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"},
		{"password", "salt", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"},
		{"password", "salt", 4096, 20, "4b007901b765489abead49d926f721d065a429c1"},
		{
			"passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt",
			4096, 25, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
		},
	} {
		got, err := PBKDF2([]byte(tc.password), []byte(tc.salt), tc.iter, tc.dkLen, sha1.New)
		if err != nil {
			t.Fatalf("PBKDF2: %v", err)
		}
		if hex.EncodeToString(got) != tc.want {
			t.Errorf("PBKDF2(%q, %q, %d, %d) = %x, want %s",
				tc.password, tc.salt, tc.iter, tc.dkLen, got, tc.want)
		}
	}
}

// TestPBKDF2SHA2 checks the widely published PBKDF2-HMAC-SHA-256 and SHA-512
// vectors, the PRFs the PBES2 algorithms actually use.
func TestPBKDF2SHA2(t *testing.T) {
	for _, tc := range []struct {
		name        string
		newHash     func() hash.Hash
		iter, dkLen int
		want        string
	}{
		{"SHA-256 c=1", sha256.New, 1, 32,
			"120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
		{"SHA-256 c=4096", sha256.New, 4096, 32,
			"c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
		{"SHA-512 c=4096", sha512.New, 4096, 64,
			"d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5" +
				"143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PBKDF2([]byte("password"), []byte("salt"), tc.iter, tc.dkLen, tc.newHash)
			if err != nil {
				t.Fatalf("PBKDF2: %v", err)
			}
			if hex.EncodeToString(got) != tc.want {
				t.Errorf("= %x\nwant %s", got, tc.want)
			}
		})
	}
}

// TestPBKDF2Rejects checks the argument guards.
func TestPBKDF2Rejects(t *testing.T) {
	if _, err := PBKDF2([]byte("p"), []byte("s"), 0, 16, sha256.New); !errors.Is(err, ErrIterationCount) {
		t.Errorf("iterations=0: err = %v", err)
	}
	if _, err := PBKDF2([]byte("p"), []byte("s"), 1, 0, sha256.New); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("keyLen=0: err = %v", err)
	}
}

// TestPBES2SaltInput checks the RFC 7518 §4.8.1.1 salt construction, which
// prefixes the algorithm name and a zero octet to the "p2s" value.
func TestPBES2SaltInput(t *testing.T) {
	got := pbes2SaltInput(PBES2_HS256_A128KW, []byte{1, 2, 3})
	want := append([]byte(PBES2_HS256_A128KW), 0x00, 1, 2, 3)
	if !bytes.Equal(got, want) {
		t.Errorf("= %q, want %q", got, want)
	}
}

// --- Concat KDF (NIST SP 800-56A, RFC 7518 §4.6.2) ---

// TestConcatKDFRFC7518AppendixC runs the worked ECDH-ES example of RFC 7518
// Appendix C, the vector that catches AlgorithmID/PartyInfo/SuppPubInfo
// encoding mistakes.
func TestConcatKDFRFC7518AppendixC(t *testing.T) {
	z := []byte{
		158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132,
		38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121,
		140, 254, 144, 196,
	}
	got, err := ConcatKDF(z, A128GCM, []byte("Alice"), []byte("Bob"), 16)
	if err != nil {
		t.Fatalf("ConcatKDF: %v", err)
	}
	want := []byte{86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26}
	if !bytes.Equal(got, want) {
		t.Errorf("= %v\nwant %v", got, want)
	}
	if EncodeSegment(got) != "VqqN6vgjbSBcIijNcacQGg" {
		t.Errorf("base64url = %q", EncodeSegment(got))
	}
}

// TestConcatKDFLongerThanHash exercises the counter loop past one hash block.
func TestConcatKDFLongerThanHash(t *testing.T) {
	out, err := ConcatKDF([]byte("shared secret"), A256CBC_HS512, nil, nil, 64)
	if err != nil {
		t.Fatalf("ConcatKDF: %v", err)
	}
	if len(out) != 64 {
		t.Fatalf("len = %d, want 64", len(out))
	}
	// The two 32-octet halves come from different counter values and must
	// differ.
	if bytes.Equal(out[:32], out[32:]) {
		t.Error("both KDF blocks are identical")
	}
	if _, err := ConcatKDF([]byte("z"), A128GCM, nil, nil, 0); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("keyLen=0: err = %v", err)
	}
}

// TestConcatKDFPartyInfoIsBound checks that apu and apv change the derived key
// and are not interchangeable.
func TestConcatKDFPartyInfoIsBound(t *testing.T) {
	base, _ := ConcatKDF([]byte("z"), A128GCM, []byte("A"), []byte("B"), 16)
	swapped, _ := ConcatKDF([]byte("z"), A128GCM, []byte("B"), []byte("A"), 16)
	none, _ := ConcatKDF([]byte("z"), A128GCM, nil, nil, 16)
	otherAlg, _ := ConcatKDF([]byte("z"), A256GCM, []byte("A"), []byte("B"), 16)
	for _, other := range [][]byte{swapped, none, otherAlg} {
		if bytes.Equal(base, other) {
			t.Error("Concat KDF output does not depend on all of its inputs")
		}
	}
}

// --- AES-CBC-HMAC-SHA2 (RFC 7518 §5.2) ---

// TestCBCHMACRFC7518AppendixB runs the three complete test cases of RFC 7518
// Appendix B: fixed key, IV, AAD, ciphertext, and truncated tag.
func TestCBCHMACRFC7518AppendixB(t *testing.T) {
	const (
		plaintext = "A cipher system must not be required to be secret, and it must be " +
			"able to fall into the hands of the enemy without inconvenience"
		aadHex = "546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673"
		ivHex  = "1af38c2dc2b96ffdd86694092341bc04"
	)
	for _, tc := range []struct {
		enc    string
		keyHex string
		ctHex  string
		tagHex string
	}{
		{
			A128CBC_HS256,
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			"c80edfa32ddf39d5ef00c0b468834279a2e46a1b8049f792f76bfe54b903a9c9" +
				"a94ac9b47ad2655c5f10f9aef71427e2fc6f9b3f399a221489f16362c7032336" +
				"09d45ac69864e3321cf82935ac4096c86e133314c54019e8ca7980dfa4b9cf1b" +
				"384c486f3a54c51078158ee5d79de59fbd34d848b3d69550a67646344427ade5" +
				"4b8851ffb598f7f80074b9473c82e2db",
			"652c3fa36b0a7c5b3219fab3a30bc1c4",
		},
		{
			A192CBC_HS384,
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
				"202122232425262728292a2b2c2d2e2f",
			"ea65da6b59e61edb419be62d19712ae5d303eeb50052d0dfd6697f77224c8edb" +
				"000d279bdc14c1072654bd30944230c657bed4ca0c9f4a8466f22b226d174621" +
				"4bf8cfc2400add9f5126e479663fc90b3bed787a2f0ffcbf3904be2a641d5c21" +
				"05bfe591bae23b1d7449e532eef60a9ac8bb6c6b01d35d49787bcd57ef484927" +
				"f280adc91ac0c4e79c7b11efc60054e3",
			"8490ac0e58949bfe51875d733f93ac2075168039ccc733d7",
		},
		{
			A256CBC_HS512,
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
				"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
			"4affaaadb78c31c5da4b1b590d10ffbd3dd8d5d302423526912da037ecbcc7bd" +
				"822c301dd67c373bccb584ad3e9279c2e6d12a1374b77f077553df829410446b" +
				"36ebd97066296ae6427ea75c2e0846a11a09ccf5370dc80bfecbad28c73f09b3" +
				"a3b75e662a2594410ae496b2e2e6609e31e6e02cc837f053d21f37ff4f51950b" +
				"be2638d09dd7a4930930806d0703b1f6",
			"4dd3b4c088a7f45c216839645b2012bf2e6269a8c56a816dbc1b267761955bc5",
		},
	} {
		t.Run(tc.enc, func(t *testing.T) {
			ce, err := lookupEnc(tc.enc)
			if err != nil {
				t.Fatal(err)
			}
			cek := mustHex(t, tc.keyHex)
			iv := mustHex(t, ivHex)
			aad := mustHex(t, aadHex)
			ct := mustHex(t, tc.ctHex)
			tag := mustHex(t, tc.tagHex)

			// The tag must reproduce exactly: this exercises the MAC/ENC key
			// split, the AAD || IV || E || AL input, the 64-bit big-endian
			// *bit* count in AL, and the truncation to half the hash length.
			macKey, _ := cbcSplit(cek)
			if got := ce.cbcTag(macKey, iv, ct, aad); !bytes.Equal(got, tag) {
				t.Errorf("tag = %x, want %x", got, tag)
			}
			if got := cbcAL(aad); hex.EncodeToString(got) != "0000000000000150" {
				t.Errorf("AL = %x, want 0000000000000150", got)
			}

			got, err := ce.decrypt(cek, iv, ct, tag, aad)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if string(got) != plaintext {
				t.Errorf("plaintext = %q", got)
			}
		})
	}
}

// TestCBCHMACRejectsTamper checks that a modified ciphertext, IV, AAD, or tag
// all fail with the same undifferentiated error — no padding oracle.
func TestCBCHMACRejectsTamper(t *testing.T) {
	ce, err := lookupEnc(A128CBC_HS256)
	if err != nil {
		t.Fatal(err)
	}
	cek := make([]byte, ce.keySize)
	for i := range cek {
		cek[i] = byte(i)
	}
	aad := []byte("protected header")
	iv, ct, tag, err := ce.encrypt(cek, []byte("hello world"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if len(iv) != 16 {
		t.Errorf("IV is %d octets, want 16", len(iv))
	}
	if len(tag) != ce.keySize/2 {
		t.Errorf("tag is %d octets, want %d", len(tag), ce.keySize/2)
	}

	mutate := func(b []byte) []byte {
		out := bytes.Clone(b)
		out[0] ^= 0x80
		return out
	}
	for name, call := range map[string]func() ([]byte, error){
		"tampered ciphertext": func() ([]byte, error) { return ce.decrypt(cek, iv, mutate(ct), tag, aad) },
		"tampered tag":        func() ([]byte, error) { return ce.decrypt(cek, iv, ct, mutate(tag), aad) },
		"tampered iv":         func() ([]byte, error) { return ce.decrypt(cek, mutate(iv), ct, tag, aad) },
		"tampered aad":        func() ([]byte, error) { return ce.decrypt(cek, iv, ct, tag, mutate(aad)) },
		"wrong key":           func() ([]byte, error) { return ce.decrypt(mutate(cek), iv, ct, tag, aad) },
		"truncated tag":       func() ([]byte, error) { return ce.decrypt(cek, iv, ct, tag[:8], aad) },
		"short ciphertext":    func() ([]byte, error) { return ce.decrypt(cek, iv, ct[:8], tag, aad) },
	} {
		if _, err := call(); !errors.Is(err, ErrDecryptFailed) {
			t.Errorf("%s: err = %v, want ErrDecryptFailed", name, err)
		}
	}
}

// TestPKCS7 checks the padding helpers, including the always-added full block.
func TestPKCS7(t *testing.T) {
	for _, n := range []int{0, 1, 15, 16, 17, 31, 32} {
		in := bytes.Repeat([]byte{0xAB}, n)
		padded := pkcs7Pad(in, 16)
		if len(padded)%16 != 0 || len(padded) <= n {
			t.Fatalf("pad(%d) produced %d octets", n, len(padded))
		}
		out, ok := pkcs7Unpad(padded, 16)
		if !ok || !bytes.Equal(out, in) {
			t.Fatalf("round trip failed for %d octets", n)
		}
	}
	for _, bad := range [][]byte{
		{},
		bytes.Repeat([]byte{0x00}, 16), // zero-length padding
		append(bytes.Repeat([]byte{0x00}, 15), 0x11), // pad longer than block
		append(bytes.Repeat([]byte{0x01}, 15), 0x02), // inconsistent padding
		bytes.Repeat([]byte{0x10}, 15),               // not a whole block
	} {
		if _, ok := pkcs7Unpad(bad, 16); ok {
			t.Errorf("pkcs7Unpad accepted %x", bad)
		}
	}
}

// TestGCMShapes checks the RFC 7518 §5.3 IV and tag sizes.
func TestGCMShapes(t *testing.T) {
	for _, name := range []string{A128GCM, A192GCM, A256GCM} {
		ce, err := lookupEnc(name)
		if err != nil {
			t.Fatal(err)
		}
		cek := make([]byte, ce.keySize)
		iv, ct, tag, err := ce.encrypt(cek, []byte("plaintext"), []byte("aad"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(iv) != 12 {
			t.Errorf("%s: IV is %d octets, want 12", name, len(iv))
		}
		if len(tag) != 16 {
			t.Errorf("%s: tag is %d octets, want 16", name, len(tag))
		}
		if len(ct) != len("plaintext") {
			t.Errorf("%s: ciphertext is %d octets, want %d", name, len(ct), len("plaintext"))
		}
		got, err := ce.decrypt(cek, iv, ct, tag, []byte("aad"))
		if err != nil || string(got) != "plaintext" {
			t.Errorf("%s: round trip failed: %q %v", name, got, err)
		}
		tag[0] ^= 1
		if _, err := ce.decrypt(cek, iv, ct, tag, []byte("aad")); !errors.Is(err, ErrDecryptFailed) {
			t.Errorf("%s: tampered tag err = %v", name, err)
		}
	}
}
