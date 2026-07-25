package jose

// Upstream-parity tests. Every case below is a concrete known-answer vector
// taken verbatim (or hand-transcribed, see testdata/UPSTREAM.md) from the
// normative JOSE conformance corpus that the upstream library this package
// mirrors — panva/jose (https://github.com/panva/jose) — also tests against:
//
//   - RFC 7520, "Examples of Protecting Content Using JOSE" (the "JOSE
//     Cookbook"), §3 JWK / §4 JWS / §5 JWE, in machine-readable form from
//     https://github.com/ietf-jose/cookbook @ 13692b68bfc1 (Unlicense),
//     cross-checked against https://www.rfc-editor.org/rfc/rfc7520.txt
//   - RFC 7515 Appendix A — JWS examples (compact A.1–A.5, JSON A.6–A.7)
//   - RFC 7516 Appendix A — JWE examples (compact A.1–A.3, JSON A.4–A.5)
//   - RFC 7517 Appendix A — JWK Set examples (public, private, symmetric)
//   - RFC 7518 — JWA; algorithm semantics only, it publishes no end-to-end
//     serializations beyond those already covered above
//   - RFC 7638 §3.1 — the JWK Thumbprint worked example
//   - RFC 8037 — CFRG curves in JOSE (Ed25519 signing, X25519 ECDH-ES), from
//     the cookbook's curve25519/ directory
//   - RFC 7797 — the JWS Unencoded Payload Option ("b64": false), from the
//     cookbook's rfc7797/ directory
//
// Vectors are asserted against this package's real exported Go API
// (Sign / Verify / VerifyWithOptions / VerifyJSON / VerifyJSONWithOptions /
// Decrypt / DecryptJSON / ParseJWK / ParseJWKSet / JWK.Thumbprint). Subtests
// are named by RFC section number, so a failure names the exact vector — e.g.
// TestUpstreamParity/rfc7520/5.5_key_agreement_using_ecdh-es_with_aes-cbc-hmac-sha2/compact.
//
// What is deliberately NOT in this corpus, so the reported score is not
// mistaken for total JOSE coverage: RFC 7520 §6 (nesting a JWS inside a JWE),
// RFC 7517 Appendix B/C (x5c certificate chains and PBES2-encrypted JWKs), and
// encrypt-side reproduction of any JWE vector (impossible by construction — see
// asymmetry 2 below).
//
// Two deliberate asymmetries in what is asserted:
//
//  1. JWS re-signing is compared byte-for-byte only for the *deterministic*
//     signature algorithms — HMAC (HS256/384/512), RSASSA-PKCS1-v1_5
//     (RS256/384/512), and EdDSA over Ed25519, whose nonce RFC 8032 derives
//     from the key and message. RSASSA-PSS (PS*) salts every signature and
//     ECDSA (ES*) draws a fresh random nonce k per signature, so two correct
//     signatures over the same input differ; for those the only sound
//     assertion is that verifying the RFC's signature with the RFC's key
//     succeeds.
//  2. JWE is asserted decrypt-side only. Re-encrypting cannot reproduce the
//     RFC's serialization because the CEK and the IV are freshly random on
//     every encryption (and RSA-OAEP / RSA1_5 / ECDH-ES add their own
//     randomness on top), so "decrypt the RFC's ciphertext and get the RFC's
//     plaintext back" is the meaningful conformance assertion.
//
// knownGaps is an allowlist of vector IDs this port does not yet satisfy. It
// keeps CI green while the true score is still measured honestly: gapped cases
// count against the denominator and the measured pass rate is t.Log'd at the
// end of the run (and copied into parity.json).

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// knownGaps maps a parity vector ID to the reason this port does not yet pass
// it. Populated from a real `go test ./...` run — never speculatively. Entries
// are skipped but still counted in the denominator, so allowlisting a vector
// lowers the reported score rather than hiding the failure.
//
// It is currently empty: every synced upstream case passes. The six entries it
// previously held were all the same gap — JWE published only in the JSON
// serialization (RFC 7520 §5.10–§5.13, RFC 7516 A.4/A.5), unreachable while the
// API offered no DecryptJSON. That surface now exists and all six were verified
// to pass before being removed here.
var knownGaps = map[string]string{}

// ---------------------------------------------------------------------------
// scoreboard
// ---------------------------------------------------------------------------

// board tallies synced upstream cases so the run reports a real pass rate.
type board struct {
	total    int
	passed   int
	failed   []string
	gapped   []string
	fixtures int
}

// run executes one upstream vector as a named subtest and records the result.
// Cases listed in knownGaps are skipped but still counted in the denominator.
func (b *board) run(t *testing.T, id string, fn func(t *testing.T)) {
	t.Helper()
	b.total++
	if reason, ok := knownGaps[id]; ok {
		b.gapped = append(b.gapped, id)
		t.Run(id, func(t *testing.T) { t.Skipf("known gap: %s", reason) })
		return
	}
	if t.Run(id, fn) {
		b.passed++
		return
	}
	b.failed = append(b.failed, id)
}

func (b *board) report(t *testing.T) {
	t.Helper()
	pct := 0.0
	if b.total > 0 {
		pct = 100 * float64(b.passed) / float64(b.total)
	}
	sort.Strings(b.failed)
	sort.Strings(b.gapped)
	t.Logf("upstream parity: %d/%d cases pass (%.1f%%) across %d vendored fixtures",
		b.passed, b.total, pct, b.fixtures)
	for _, id := range b.gapped {
		t.Logf("  gap (allowlisted): %s", id)
	}
	for _, id := range b.failed {
		t.Logf("  FAIL (not allowlisted): %s", id)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func b64uDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		t.Fatalf("base64url decode %q: %v", s, err)
	}
	return b
}

func b64uEncode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func readFixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read fixture %s: %v", rel, err)
	}
	return b
}

func fixtureGlob(t *testing.T, pattern string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join("testdata", filepath.FromSlash(pattern)))
	if err != nil || len(m) == 0 {
		t.Fatalf("glob %s: %v (matched %d)", pattern, err, len(m))
	}
	sort.Strings(m)
	return m
}

// parseJWKMap turns a decoded JWK object back into bytes and through ParseJWK,
// so the exported parser is what is under test rather than a shortcut.
func parseJWKMap(t *testing.T, m map[string]any) *JWK {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("re-marshal JWK: %v", err)
	}
	k, err := ParseJWK(raw)
	if err != nil {
		t.Fatalf("ParseJWK: %v", err)
	}
	return k
}

// verificationKey returns the key to hand to Verify/VerifyJSON: the public half
// for asymmetric JWKs, the raw octets for symmetric ones.
func verificationKey(t *testing.T, m map[string]any) any {
	t.Helper()
	k := parseJWKMap(t, m)
	if kty, _ := m["kty"].(string); kty != "oct" {
		pub, err := k.Public()
		if err != nil {
			t.Fatalf("JWK.Public: %v", err)
		}
		k = pub
	}
	key, err := k.Key()
	if err != nil {
		t.Fatalf("JWK.Key: %v", err)
	}
	return key
}

// privateKey returns the signing/decryption key for a JWK object.
func privateKey(t *testing.T, m map[string]any) any {
	t.Helper()
	key, err := parseJWKMap(t, m).Key()
	if err != nil {
		t.Fatalf("JWK.Key: %v", err)
	}
	return key
}

// deterministicAlg reports whether re-signing with alg must reproduce the exact
// signature octets. HMAC and RSASSA-PKCS1-v1_5 are deterministic; RSASSA-PSS
// (random salt) and ECDSA (random nonce k) are not. EdDSA is also deterministic
// but is not reached through this helper — it is asserted directly by
// parityRFC8037.
func deterministicAlg(alg string) bool {
	return strings.HasPrefix(alg, "HS") || strings.HasPrefix(alg, "RS")
}

// canonicalProtected reports whether the vector's protected header is byte-equal
// to a canonical compact JSON re-serialization of itself. Several RFC examples
// embed literal CRLFs and spaces inside the protected header (RFC 7515 A.1) or
// order members non-alphabetically; re-signing can never reproduce those octets
// no matter how correct the signature algorithm is, so the byte-for-byte check
// is only meaningful when this holds.
func canonicalProtected(protectedB64U string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(protectedB64U, "="))
	if err != nil {
		return false
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return false
	}
	re, err := json.Marshal(m)
	if err != nil {
		return false
	}
	return bytes.Equal(raw, re)
}

// splitCompact splits a compact serialization, tolerating empty segments.
func splitCompact(s string) []string { return strings.Split(s, ".") }

// sectionOf turns "4_1.rsa_v15_signature.json" into ("4.1", "rsa_v15_signature").
func sectionOf(path string) (section, slug string) {
	name := strings.TrimSuffix(filepath.Base(path), ".json")
	parts := strings.SplitN(name, ".", 2)
	section = strings.ReplaceAll(parts[0], "_", ".")
	if len(parts) > 1 {
		slug = parts[1]
	}
	return section, slug
}

// ---------------------------------------------------------------------------
// RFC 7520 cookbook fixture shapes
// ---------------------------------------------------------------------------

type cookbookVector struct {
	Title   string          `json:"title"`
	Input   cookbookInput   `json:"input"`
	Signing json.RawMessage `json:"signing"`
	Output  cookbookOutput  `json:"output"`
}

type cookbookInput struct {
	Payload   string          `json:"payload"`
	Plaintext string          `json:"plaintext"`
	Pwd       string          `json:"pwd"`
	Key       json.RawMessage `json:"key"`
	Alg       json.RawMessage `json:"alg"`
	Enc       string          `json:"enc"`
	Zip       string          `json:"zip"`
	Aad       string          `json:"aad"`
}

type cookbookOutput struct {
	Compact  string          `json:"compact"`
	JSON     json.RawMessage `json:"json"`
	JSONFlat json.RawMessage `json:"json_flat"`
}

// keys returns the vector's input key(s); the cookbook uses a bare object for
// single-key examples and an array for the multi-signature/multi-recipient ones.
func (in cookbookInput) keys(t *testing.T) []map[string]any {
	t.Helper()
	if len(in.Key) == 0 {
		return nil
	}
	var one map[string]any
	if err := json.Unmarshal(in.Key, &one); err == nil {
		return []map[string]any{one}
	}
	var many []map[string]any
	if err := json.Unmarshal(in.Key, &many); err != nil {
		t.Fatalf("decode input.key: %v", err)
	}
	return many
}

func (in cookbookInput) algs(t *testing.T) []string {
	t.Helper()
	var one string
	if err := json.Unmarshal(in.Alg, &one); err == nil {
		return []string{one}
	}
	var many []string
	if err := json.Unmarshal(in.Alg, &many); err != nil {
		t.Fatalf("decode input.alg: %v", err)
	}
	return many
}

// signingHeader returns the first signing step's protected header (decoded) and
// its base64url form, for the single-signature vectors.
func signingHeader(t *testing.T, raw json.RawMessage) (hdr map[string]any, b64u string) {
	t.Helper()
	if len(raw) == 0 {
		return nil, ""
	}
	var one struct {
		Protected     map[string]any `json:"protected"`
		ProtectedB64U string         `json:"protected_b64u"`
	}
	if err := json.Unmarshal(raw, &one); err == nil {
		return one.Protected, one.ProtectedB64U
	}
	return nil, ""
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

func TestUpstreamParity(t *testing.T) {
	b := &board{}
	parityRFC7520JWK(t, b)
	parityRFC7520JWS(t, b)
	parityRFC7520JWE(t, b)
	parityRFC7515(t, b)
	parityRFC7516(t, b)
	parityRFC7517(t, b)
	parityRFC7638(t, b)
	parityRFC8037(t, b)
	parityRFC7797(t, b)
	b.report(t)
}

// ---------------------------------------------------------------------------
// RFC 7520 §3 — JWK
// ---------------------------------------------------------------------------

func parityRFC7520JWK(t *testing.T, b *board) {
	for _, path := range fixtureGlob(t, "rfc7520/jwk/*.json") {
		b.fixtures++
		section, slug := sectionOf(path)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		// The cookbook publishes each §3.x JWK as a bare JWK object.
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		jwkObj := doc
		if inner, ok := doc["key"].(map[string]any); ok {
			jwkObj = inner
		}

		b.run(t, fmt.Sprintf("rfc7520/%s_%s/parse", section, slug), func(t *testing.T) {
			k := parseJWKMap(t, jwkObj)
			if k.Kty != jwkObj["kty"].(string) {
				t.Fatalf("Kty = %q, want %q", k.Kty, jwkObj["kty"])
			}
			if kid, ok := jwkObj["kid"].(string); ok && k.Kid != kid {
				t.Fatalf("Kid = %q, want %q", k.Kid, kid)
			}
			if _, err := k.Key(); err != nil {
				t.Fatalf("JWK.Key: %v", err)
			}
			if _, err := k.Thumbprint(); err != nil {
				t.Fatalf("JWK.Thumbprint: %v", err)
			}
			if k.Kty != "oct" {
				pub, err := k.Public()
				if err != nil {
					t.Fatalf("JWK.Public: %v", err)
				}
				if pub.D != "" || pub.K != "" {
					t.Fatalf("JWK.Public leaked private material")
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// RFC 7520 §4 — JWS
// ---------------------------------------------------------------------------

func parityRFC7520JWS(t *testing.T, b *board) {
	for _, path := range fixtureGlob(t, "rfc7520/jws/*.json") {
		b.fixtures++
		section, slug := sectionOf(path)
		id := fmt.Sprintf("rfc7520/%s_%s", section, slug)

		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var v cookbookVector
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		payload := []byte(v.Input.Payload)
		keys := v.Input.keys(t)
		algs := v.Input.algs(t)
		hdr, hdrB64U := signingHeader(t, v.Signing)

		if v.Output.Compact != "" {
			b.run(t, id+"/compact", func(t *testing.T) {
				token := v.Output.Compact
				parts := splitCompact(token)
				if len(parts) == 3 && parts[1] == "" {
					// RFC 7520 §4.5 detached content: the payload travels out
					// of band. Re-attach it so the RFC's signature octets are
					// still verified against the exported compact API.
					token = parts[0] + "." + b64uEncode(payload) + "." + parts[2]
					t.Logf("detached payload re-attached for verification")
				}
				got, gotHdr, err := Verify(token, verificationKey(t, keys[0]))
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				if !bytes.Equal(got, payload) {
					t.Fatalf("payload mismatch:\n got %q\nwant %q", got, payload)
				}
				if a, _ := gotHdr["alg"].(string); a != algs[0] {
					t.Fatalf("header alg = %q, want %q", a, algs[0])
				}

				if !deterministicAlg(algs[0]) {
					t.Logf("%s is randomized (PSS salt / ECDSA nonce): verify-only, "+
						"re-signing cannot reproduce the RFC's signature octets", algs[0])
					return
				}
				if !canonicalProtected(hdrB64U) {
					t.Logf("RFC protected header is not a canonical compact JSON object; "+
						"skipping byte-for-byte re-sign comparison (header=%q)", hdrB64U)
					return
				}
				opts := SignOptions{Algorithm: algs[0]}
				extra := map[string]any{}
				for k, val := range hdr {
					switch k {
					case "alg":
					case "kid":
						opts.KeyID, _ = val.(string)
					default:
						extra[k] = val
					}
				}
				if len(extra) > 0 {
					opts.Header = extra
				}
				resigned, err := Sign(payload, privateKey(t, keys[0]), opts)
				if err != nil {
					t.Fatalf("Sign: %v", err)
				}
				// Compare against `token`, which for §4.5 is the RFC's compact
				// serialization with the detached payload re-attached.
				if resigned != token {
					t.Fatalf("re-signed token differs from RFC vector\n got %s\nwant %s",
						resigned, token)
				}
			})
		}

		if len(v.Output.JSON) > 0 {
			b.run(t, id+"/json", func(t *testing.T) {
				data := v.Output.JSON
				var obj map[string]any
				if err := json.Unmarshal(data, &obj); err != nil {
					t.Fatalf("decode output.json: %v", err)
				}
				if _, ok := obj["payload"]; !ok {
					// §4.5 detached content again.
					obj["payload"] = b64uEncode(payload)
					if data, err = json.Marshal(obj); err != nil {
						t.Fatalf("re-marshal: %v", err)
					}
				}
				// Every key listed for the vector must verify the JWS; §4.8
				// carries three independent signatures over one payload.
				for i, km := range keys {
					got, _, err := VerifyJSON(data, verificationKey(t, km))
					if err != nil {
						t.Fatalf("VerifyJSON with key %d (%s): %v", i, algs[min(i, len(algs)-1)], err)
					}
					if !bytes.Equal(got, payload) {
						t.Fatalf("payload mismatch for key %d:\n got %q\nwant %q", i, got, payload)
					}
				}
			})
		}
	}
}

// ---------------------------------------------------------------------------
// RFC 7520 §5 — JWE
// ---------------------------------------------------------------------------

func parityRFC7520JWE(t *testing.T, b *board) {
	for _, path := range fixtureGlob(t, "rfc7520/jwe/*.json") {
		b.fixtures++
		section, slug := sectionOf(path)
		id := fmt.Sprintf("rfc7520/%s_%s", section, slug)

		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var v cookbookVector
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		plaintext := []byte(v.Input.Plaintext)
		keys := v.Input.keys(t)
		algs := v.Input.algs(t)
		wantEnc := v.Input.Enc
		if wantEnc == "A128CBC-H256" {
			// Defect in the vendored fixture, not in this package: the
			// cookbook's 5_13 "input.enc" reads "A128CBC-H256" while that same
			// vector's own protected header — and every occurrence in the RFC
			// 7520 text — reads "A128CBC-HS256". The fixture is kept
			// byte-verbatim at the pinned commit, so the typo is corrected
			// here at load time instead. Recorded in testdata/UPSTREAM.md.
			wantEnc = "A128CBC-HS256"
		}

		if v.Output.Compact != "" {
			b.run(t, id+"/compact", func(t *testing.T) {
				// Decrypt-side only: the CEK and IV in every §5.x vector were
				// drawn at random when the RFC was written, so re-encrypting
				// the same plaintext with the same key can never reproduce the
				// published serialization. Recovering the exact plaintext from
				// the published serialization is the conformance assertion.
				var key any
				if v.Input.Pwd != "" {
					key = []byte(v.Input.Pwd)
				} else {
					key = privateKey(t, keys[0])
				}
				got, hdr, err := Decrypt(v.Output.Compact, key)
				if err != nil {
					t.Fatalf("Decrypt (alg=%s enc=%s): %v", algs[0], wantEnc, err)
				}
				if !bytes.Equal(got, plaintext) {
					t.Fatalf("plaintext mismatch:\n got %q\nwant %q", got, plaintext)
				}
				if a, _ := hdr["alg"].(string); a != algs[0] {
					t.Fatalf("header alg = %q, want %q", a, algs[0])
				}
				if e, _ := hdr["enc"].(string); e != wantEnc {
					t.Fatalf("header enc = %q, want %q", e, wantEnc)
				}
				if v.Input.Zip != "" {
					if z, _ := hdr["zip"].(string); z != v.Input.Zip {
						t.Fatalf("header zip = %q, want %q", z, v.Input.Zip)
					}
				}
			})
			continue
		}

		// Vectors published only in the JWE JSON serialization (§5.10–§5.13).
		b.run(t, id+"/json", func(t *testing.T) {
			// Decrypt-side only, same reasoning as the compact cases above.
			// Every key the vector lists must independently recover the
			// plaintext: §5.13 addresses one CEK to three recipients under
			// three different key-management algorithms, which is the case
			// most likely to expose a recipient-selection bug.
			forms := map[string]json.RawMessage{"general": v.Output.JSON}
			if len(v.Output.JSONFlat) > 0 {
				forms["flattened"] = v.Output.JSONFlat
			}
			formNames := make([]string, 0, len(forms))
			for name := range forms {
				formNames = append(formNames, name)
			}
			sort.Strings(formNames)

			for _, form := range formNames {
				for i, km := range keys {
					var key any
					if v.Input.Pwd != "" {
						key = []byte(v.Input.Pwd)
					} else {
						key = privateKey(t, km)
					}
					alg := algs[min(i, len(algs)-1)]
					got, hdr, err := DecryptJSON(forms[form], key)
					if err != nil {
						t.Fatalf("DecryptJSON %s form, recipient %d (alg=%s enc=%s): %v",
							form, i, alg, wantEnc, err)
					}
					if !bytes.Equal(got, plaintext) {
						t.Fatalf("plaintext mismatch (%s form, recipient %d):\n got %q\nwant %q",
							form, i, got, plaintext)
					}
					// The merged header must describe the recipient that the
					// supplied key actually unlocked, not merely the first one.
					if a, _ := hdr["alg"].(string); a != alg {
						t.Fatalf("%s form, recipient %d: header alg = %q, want %q",
							form, i, a, alg)
					}
					if e, _ := hdr["enc"].(string); e != wantEnc {
						t.Fatalf("%s form, recipient %d: header enc = %q, want %q",
							form, i, e, wantEnc)
					}
					if kid, ok := km["kid"].(string); ok && len(keys) > 1 {
						if got, _ := hdr["kid"].(string); got != kid {
							t.Fatalf("%s form, recipient %d: header kid = %q, want %q",
								form, i, got, kid)
						}
					}
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// RFC 7515 Appendix A — JWS
// ---------------------------------------------------------------------------

type rfc7515Compact struct {
	ID            string         `json:"id"`
	Title         string         `json:"title"`
	Alg           string         `json:"alg"`
	Deterministic bool           `json:"deterministic"`
	Key           map[string]any `json:"key"`
	PayloadB64U   string         `json:"payload_b64u"`
	Compact       string         `json:"compact"`
}

func parityRFC7515(t *testing.T, b *board) {
	b.fixtures++
	var vs []rfc7515Compact
	if err := json.Unmarshal(readFixture(t, "rfc7515/jws_compact.json"), &vs); err != nil {
		t.Fatalf("decode rfc7515/jws_compact.json: %v", err)
	}
	for _, v := range vs {
		id := fmt.Sprintf("rfc7515/%s_%s", v.ID, v.Alg)
		b.run(t, id+"_compact", func(t *testing.T) {
			payload := b64uDecode(t, v.PayloadB64U)

			if v.Alg == "none" {
				// RFC 7515 A.5 is the Unsecured JWS. Accepting it silently is
				// the classic algorithm-confusion hole (RFC 8725 §3.1), so the
				// conformance assertion here is that this port *rejects* it.
				if _, _, err := Verify(v.Compact, []byte("any key")); err == nil {
					t.Fatalf("Verify accepted an alg=none JWS; it must be rejected")
				}
				return
			}

			got, hdr, err := Verify(v.Compact, verificationKey(t, v.Key))
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("payload mismatch:\n got %q\nwant %q", got, payload)
			}
			if a, _ := hdr["alg"].(string); a != v.Alg {
				t.Fatalf("header alg = %q, want %q", a, v.Alg)
			}
			if !v.Deterministic {
				t.Logf("%s is randomized: verify-only", v.Alg)
				return
			}
			protectedB64U := splitCompact(v.Compact)[0]
			if !canonicalProtected(protectedB64U) {
				t.Logf("RFC protected header is not canonical JSON (it embeds CRLF and "+
					"padding spaces); skipping byte-for-byte re-sign comparison (header=%q)",
					protectedB64U)
				return
			}
			resigned, err := Sign(payload, privateKey(t, v.Key), SignOptions{Algorithm: v.Alg})
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if resigned != v.Compact {
				t.Fatalf("re-signed token differs from RFC vector\n got %s\nwant %s",
					resigned, v.Compact)
			}
		})
	}

	b.fixtures++
	var jsonVecs map[string]struct {
		ID          string                    `json:"id"`
		Title       string                    `json:"title"`
		Keys        map[string]map[string]any `json:"keys"`
		PayloadB64U string                    `json:"payload_b64u"`
		JSON        json.RawMessage           `json:"json"`
	}
	if err := json.Unmarshal(readFixture(t, "rfc7515/jws_json.json"), &jsonVecs); err != nil {
		t.Fatalf("decode rfc7515/jws_json.json: %v", err)
	}
	names := make([]string, 0, len(jsonVecs))
	for name := range jsonVecs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		v := jsonVecs[name]
		b.run(t, "rfc7515/"+name, func(t *testing.T) {
			payload := b64uDecode(t, v.PayloadB64U)
			algs := make([]string, 0, len(v.Keys))
			for alg := range v.Keys {
				algs = append(algs, alg)
			}
			sort.Strings(algs)
			for _, alg := range algs {
				got, _, err := VerifyJSON(v.JSON, verificationKey(t, v.Keys[alg]))
				if err != nil {
					t.Fatalf("VerifyJSON (%s): %v", alg, err)
				}
				if !bytes.Equal(got, payload) {
					t.Fatalf("payload mismatch (%s):\n got %q\nwant %q", alg, got, payload)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// RFC 7516 Appendix A — JWE
// ---------------------------------------------------------------------------

func parityRFC7516(t *testing.T, b *board) {
	b.fixtures++
	var vs []struct {
		ID        string         `json:"id"`
		Title     string         `json:"title"`
		Alg       string         `json:"alg"`
		Enc       string         `json:"enc"`
		Key       map[string]any `json:"key"`
		Plaintext string         `json:"plaintext"`
		Compact   string         `json:"compact"`
	}
	if err := json.Unmarshal(readFixture(t, "rfc7516/jwe_compact.json"), &vs); err != nil {
		t.Fatalf("decode rfc7516/jwe_compact.json: %v", err)
	}
	for _, v := range vs {
		b.run(t, "rfc7516/"+v.ID+"_compact", func(t *testing.T) {
			// Decrypt-side only, for the same reason as the RFC 7520 §5 cases.
			got, hdr, err := Decrypt(v.Compact, privateKey(t, v.Key))
			if err != nil {
				t.Fatalf("Decrypt (alg=%s enc=%s): %v", v.Alg, v.Enc, err)
			}
			if string(got) != v.Plaintext {
				t.Fatalf("plaintext mismatch:\n got %q\nwant %q", got, v.Plaintext)
			}
			if a, _ := hdr["alg"].(string); a != v.Alg {
				t.Fatalf("header alg = %q, want %q", a, v.Alg)
			}
			if e, _ := hdr["enc"].(string); e != v.Enc {
				t.Fatalf("header enc = %q, want %q", e, v.Enc)
			}
		})
	}

	b.fixtures++
	var jsonVecs map[string]struct {
		ID        string                    `json:"id"`
		Plaintext string                    `json:"plaintext"`
		Keys      map[string]map[string]any `json:"keys"`
		JSON      json.RawMessage           `json:"json"`
	}
	if err := json.Unmarshal(readFixture(t, "rfc7516/jwe_json.json"), &jsonVecs); err != nil {
		t.Fatalf("decode rfc7516/jwe_json.json: %v", err)
	}
	names := make([]string, 0, len(jsonVecs))
	for name := range jsonVecs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		v := jsonVecs[name]
		b.run(t, "rfc7516/"+name, func(t *testing.T) {
			// A.4 is the general serialization with two recipients (RSA1_5 and
			// A128KW over one shared CEK); A.5 is the flattened form of A.4's
			// second recipient. Each listed key must independently decrypt.
			algs := make([]string, 0, len(v.Keys))
			for alg := range v.Keys {
				algs = append(algs, alg)
			}
			sort.Strings(algs)
			for _, alg := range algs {
				got, hdr, err := DecryptJSON(v.JSON, privateKey(t, v.Keys[alg]))
				if err != nil {
					t.Fatalf("DecryptJSON (alg=%s): %v", alg, err)
				}
				if string(got) != v.Plaintext {
					t.Fatalf("plaintext mismatch (alg=%s):\n got %q\nwant %q", alg, got, v.Plaintext)
				}
				if a, _ := hdr["alg"].(string); a != alg {
					t.Fatalf("header alg = %q, want %q", a, alg)
				}
				if e, _ := hdr["enc"].(string); e != "A128CBC-HS256" {
					t.Fatalf("header enc = %q, want A128CBC-HS256", e)
				}
				// "jku" lives in the shared unprotected header; the merged
				// header must surface it alongside the protected "enc".
				if jku, _ := hdr["jku"].(string); jku != "https://server.example.com/keys.jwks" {
					t.Fatalf("header jku = %q, want the shared unprotected value", jku)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// RFC 7517 Appendix A — JWK Sets
// ---------------------------------------------------------------------------

func parityRFC7517(t *testing.T, b *board) {
	cases := []struct {
		id      string
		file    string
		wantKid []string
	}{
		{"rfc7517/A.1_public_keys", "rfc7517/a1_public_keys.json", []string{"1", "2011-04-29"}},
		{"rfc7517/A.2_private_keys", "rfc7517/a2_private_keys.json", []string{"1", "2011-04-29"}},
		{"rfc7517/A.3_symmetric_keys", "rfc7517/a3_symmetric_keys.json",
			[]string{"", "HMAC key used in JWS spec Appendix A.1 example"}},
	}
	for _, c := range cases {
		b.fixtures++
		b.run(t, c.id, func(t *testing.T) {
			set, err := ParseJWKSet(readFixture(t, c.file))
			if err != nil {
				t.Fatalf("ParseJWKSet: %v", err)
			}
			if len(set.Keys) != len(c.wantKid) {
				t.Fatalf("got %d keys, want %d", len(set.Keys), len(c.wantKid))
			}
			for i, k := range set.Keys {
				if k.Kid != c.wantKid[i] {
					t.Fatalf("key %d kid = %q, want %q", i, k.Kid, c.wantKid[i])
				}
				if _, err := k.Key(); err != nil {
					t.Fatalf("key %d (%s) Key(): %v", i, k.Kty, err)
				}
				if _, err := k.Thumbprint(); err != nil {
					t.Fatalf("key %d (%s) Thumbprint(): %v", i, k.Kty, err)
				}
				if k.Kid == "" {
					continue
				}
				found, ok := set.LookupKeyID(k.Kid)
				if !ok || found.Kid != k.Kid {
					t.Fatalf("LookupKeyID(%q) failed", k.Kid)
				}
			}
			// ParseJWK must also accept a single key extracted from the set.
			raw, err := json.Marshal(map[string]any{
				"kty": set.Keys[0].Kty, "crv": set.Keys[0].Crv,
				"x": set.Keys[0].X, "y": set.Keys[0].Y,
				"n": set.Keys[0].N, "e": set.Keys[0].E, "k": set.Keys[0].K,
			})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if _, err := ParseJWK(raw); err != nil {
				t.Fatalf("ParseJWK on extracted key: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// RFC 7638 §3.1 — JWK Thumbprint
// ---------------------------------------------------------------------------

func parityRFC7638(t *testing.T, b *board) {
	b.fixtures++
	var v struct {
		ID         string         `json:"id"`
		JWK        map[string]any `json:"jwk"`
		Canonical  string         `json:"canonical"`
		Thumbprint string         `json:"thumbprint"`
	}
	if err := json.Unmarshal(readFixture(t, "rfc7638/thumbprint.json"), &v); err != nil {
		t.Fatalf("decode rfc7638/thumbprint.json: %v", err)
	}
	b.run(t, "rfc7638/3.1_jwk_thumbprint", func(t *testing.T) {
		k := parseJWKMap(t, v.JWK)
		got, err := k.Thumbprint()
		if err != nil {
			t.Fatalf("Thumbprint: %v", err)
		}
		if got != v.Thumbprint {
			t.Fatalf("Thumbprint = %q, want %q", got, v.Thumbprint)
		}
	})
}

// ---------------------------------------------------------------------------
// RFC 8037 — CFRG curves (Ed25519 JWS, X25519 ECDH-ES)
// ---------------------------------------------------------------------------

// parityRFC8037 drives the JOSE Cookbook's CFRG-curve vectors. These live in
// the cookbook's curve25519/ directory rather than in RFC 7520 itself, and they
// exercise RFC 8037 "CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures
// in JOSE": OKP keys with crv Ed25519 (signing) and X25519 (key agreement).
func parityRFC8037(t *testing.T, b *board) {
	// Ed25519 JWS. EdDSA over Ed25519 is deterministic by construction
	// (RFC 8032 derives the nonce from the key and message), so unlike ECDSA
	// this one *must* re-sign to the RFC's exact octets.
	b.fixtures++
	var jws cookbookVector
	if err := json.Unmarshal(readFixture(t, "rfc8037/ed25519_jws.json"), &jws); err != nil {
		t.Fatalf("decode rfc8037/ed25519_jws.json: %v", err)
	}
	jwsKeys := jws.Input.keys(t)
	jwsAlgs := jws.Input.algs(t)
	jwsPayload := []byte(jws.Input.Payload)

	b.run(t, "rfc8037/ed25519_jws/compact", func(t *testing.T) {
		got, hdr, err := Verify(jws.Output.Compact, verificationKey(t, jwsKeys[0]))
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !bytes.Equal(got, jwsPayload) {
			t.Fatalf("payload mismatch:\n got %q\nwant %q", got, jwsPayload)
		}
		if a, _ := hdr["alg"].(string); a != jwsAlgs[0] {
			t.Fatalf("header alg = %q, want %q", a, jwsAlgs[0])
		}
		resigned, err := Sign(jwsPayload, privateKey(t, jwsKeys[0]),
			SignOptions{Algorithm: jwsAlgs[0]})
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if resigned != jws.Output.Compact {
			t.Fatalf("re-signed token differs from vector\n got %s\nwant %s",
				resigned, jws.Output.Compact)
		}
	})

	b.run(t, "rfc8037/ed25519_jws/json", func(t *testing.T) {
		for _, form := range []struct {
			name string
			data json.RawMessage
		}{{"general", jws.Output.JSON}, {"flattened", jws.Output.JSONFlat}} {
			if len(form.data) == 0 {
				continue
			}
			got, _, err := VerifyJSON(form.data, verificationKey(t, jwsKeys[0]))
			if err != nil {
				t.Fatalf("VerifyJSON (%s form): %v", form.name, err)
			}
			if !bytes.Equal(got, jwsPayload) {
				t.Fatalf("payload mismatch (%s form):\n got %q\nwant %q",
					form.name, got, jwsPayload)
			}
		}
	})

	// X25519 ECDH-ES. Decrypt-side only: the ephemeral key and the IV are
	// freshly random on every encryption.
	b.fixtures++
	var jwe cookbookVector
	if err := json.Unmarshal(readFixture(t, "rfc8037/x25519_ecdh-es.json"), &jwe); err != nil {
		t.Fatalf("decode rfc8037/x25519_ecdh-es.json: %v", err)
	}
	jweKeys := jwe.Input.keys(t)
	jweAlgs := jwe.Input.algs(t)
	jwePlaintext := []byte(jwe.Input.Plaintext)

	b.run(t, "rfc8037/x25519_ecdh-es/compact", func(t *testing.T) {
		got, hdr, err := Decrypt(jwe.Output.Compact, privateKey(t, jweKeys[0]))
		if err != nil {
			t.Fatalf("Decrypt (alg=%s enc=%s): %v", jweAlgs[0], jwe.Input.Enc, err)
		}
		if !bytes.Equal(got, jwePlaintext) {
			t.Fatalf("plaintext mismatch:\n got %q\nwant %q", got, jwePlaintext)
		}
		if a, _ := hdr["alg"].(string); a != jweAlgs[0] {
			t.Fatalf("header alg = %q, want %q", a, jweAlgs[0])
		}
		if e, _ := hdr["enc"].(string); e != jwe.Input.Enc {
			t.Fatalf("header enc = %q, want %q", e, jwe.Input.Enc)
		}
	})

	b.run(t, "rfc8037/x25519_ecdh-es/json", func(t *testing.T) {
		for _, form := range []struct {
			name string
			data json.RawMessage
		}{{"general", jwe.Output.JSON}, {"flattened", jwe.Output.JSONFlat}} {
			if len(form.data) == 0 {
				continue
			}
			got, _, err := DecryptJSON(form.data, privateKey(t, jweKeys[0]))
			if err != nil {
				t.Fatalf("DecryptJSON (%s form): %v", form.name, err)
			}
			if !bytes.Equal(got, jwePlaintext) {
				t.Fatalf("plaintext mismatch (%s form):\n got %q\nwant %q",
					form.name, got, jwePlaintext)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// RFC 7797 — JWS Unencoded Payload Option ("b64": false)
// ---------------------------------------------------------------------------

// parityRFC7797 drives the cookbook's "b64": false vectors. With b64 false the
// payload is fed into the signing input raw rather than base64url-encoded, and
// "b64" must be listed in "crit" — so verifying these also exercises crit
// handling. The payload member of the JSON serialization is likewise literal,
// not base64url.
func parityRFC7797(t *testing.T, b *board) {
	for _, name := range []string{"b64_false_compact", "b64_false_json_only"} {
		b.fixtures++
		var v cookbookVector
		if err := json.Unmarshal(readFixture(t, "rfc7797/"+name+".json"), &v); err != nil {
			t.Fatalf("decode rfc7797/%s.json: %v", name, err)
		}
		keys := v.Input.keys(t)
		payload := []byte(v.Input.Payload)

		if v.Output.Compact != "" {
			b.run(t, "rfc7797/"+name+"/compact", func(t *testing.T) {
				got, hdr, err := VerifyWithOptions(v.Output.Compact,
					verificationKey(t, keys[0]),
					VerifyOptions{KnownCritical: []string{"b64"}})
				if err != nil {
					t.Fatalf("VerifyWithOptions: %v", err)
				}
				if !bytes.Equal(got, payload) {
					t.Fatalf("payload mismatch:\n got %q\nwant %q", got, payload)
				}
				if b64, ok := hdr["b64"].(bool); !ok || b64 {
					t.Fatalf("header b64 = %v, want false", hdr["b64"])
				}
			})
		}

		b.run(t, "rfc7797/"+name+"/json", func(t *testing.T) {
			for _, form := range []struct {
				name string
				data json.RawMessage
			}{{"general", v.Output.JSON}, {"flattened", v.Output.JSONFlat}} {
				if len(form.data) == 0 {
					continue
				}
				got, _, err := VerifyJSONWithOptions(form.data,
					verificationKey(t, keys[0]),
					VerifyOptions{KnownCritical: []string{"b64"}})
				if err != nil {
					t.Fatalf("VerifyJSONWithOptions (%s form): %v", form.name, err)
				}
				if !bytes.Equal(got, payload) {
					t.Fatalf("payload mismatch (%s form):\n got %q\nwant %q",
						form.name, got, payload)
				}
			}
		})
	}
}
