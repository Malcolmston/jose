package jose

import (
	"encoding/json"
	"fmt"
	"strings"
)

// SignOptions configures the production of a JWS (RFC 7515).
type SignOptions struct {
	// Algorithm is the JWS "alg" value, e.g. "RS256" or "EdDSA". When empty,
	// Sign infers the conventional algorithm for the key's type.
	Algorithm string

	// KeyID, when non-empty, is written to the protected "kid" header.
	KeyID string

	// Header holds additional protected header parameters. They are covered
	// by the signature.
	Header map[string]any

	// Unprotected holds header parameters that are *not* covered by the
	// signature. They can only be carried by the JSON serializations, so
	// Sign (which produces the compact serialization) rejects them.
	Unprotected map[string]any

	// Critical lists the extension header names to advertise in "crit". Each
	// name must also appear in Header.
	Critical []string

	// DetachPayload omits the payload from the serialization (RFC 7515
	// Appendix F). The payload is still covered by the signature and must be
	// supplied out of band at verification time via
	// VerifyOptions.DetachedPayload.
	//
	// Setting Header["b64"] = false additionally selects the RFC 7797
	// unencoded payload option, in which case "b64" must be listed in
	// Critical.
	DetachPayload bool
}

// VerifyOptions configures JWS verification. The zero value is what Verify and
// VerifyJSON use.
type VerifyOptions struct {
	// Algorithms, when non-empty, restricts the accepted "alg" values. This
	// is the strongest defense against algorithm confusion and should be set
	// whenever the expected algorithm is known.
	Algorithms []string

	// KnownCritical lists extension header names the caller understands and
	// processes out of band. "b64" (RFC 7797) is always understood; any other
	// name in "crit" that is not listed here causes rejection.
	KnownCritical []string

	// DetachedPayload supplies the payload for a JWS serialized without one.
	DetachedPayload []byte
}

// Signer pairs a key with the options used to produce one signature, for
// building a multi-signature JWS with SignJSONMulti.
type Signer struct {
	// Key is the signing key: a Go crypto key, a []byte secret, or a *JWK.
	Key any
	// Options configures this signature.
	Options SignOptions
}

// jwsJSON is the general JWS JSON serialization (RFC 7515 §7.2.1). It also
// accepts the flattened form (§7.2.2) on decode.
type jwsJSON struct {
	Payload    string         `json:"payload"`
	Signatures []jwsSignature `json:"signatures,omitempty"`

	// Flattened form.
	Protected string         `json:"protected,omitempty"`
	Header    map[string]any `json:"header,omitempty"`
	Signature string         `json:"signature,omitempty"`
}

// jwsSignature is one entry of the "signatures" array.
type jwsSignature struct {
	Protected string         `json:"protected,omitempty"`
	Header    map[string]any `json:"header,omitempty"`
	Signature string         `json:"signature"`
}

// Sign signs payload and returns the JWS compact serialization
// "protected.payload.signature".
//
// key may be a Go crypto key ([]byte, *rsa.PrivateKey, *ecdsa.PrivateKey,
// ed25519.PrivateKey) or a *JWK carrying one. Every algorithm type-asserts the
// key it is given, so an "alg" can never be used with a key of the wrong type.
func Sign(payload []byte, key any, opts SignOptions) (string, error) {
	if len(opts.Unprotected) > 0 {
		return "", fmt.Errorf("%w: the compact serialization cannot carry unprotected headers", ErrInvalidHeader)
	}
	protectedB64, sigB64, encodedPayload, err := signOne(payload, key, opts)
	if err != nil {
		return "", err
	}
	if opts.DetachPayload {
		encodedPayload = ""
	}
	return protectedB64 + "." + encodedPayload + "." + sigB64, nil
}

// SignJSON signs payload and returns the general JWS JSON serialization with a
// single signature. Parameters in SignOptions.Unprotected are carried in the
// per-signature unprotected "header" member.
func SignJSON(payload []byte, key any, opts SignOptions) ([]byte, error) {
	return SignJSONMulti(payload, Signer{Key: key, Options: opts})
}

// SignJSONMulti signs payload once per signer and returns the general JWS JSON
// serialization carrying all of the signatures (RFC 7515 §7.2.1). Every signer
// must agree on whether the payload is detached and on the RFC 7797 "b64"
// setting, since the payload is serialized only once.
func SignJSONMulti(payload []byte, signers ...Signer) ([]byte, error) {
	if len(signers) == 0 {
		return nil, fmt.Errorf("%w: no signers supplied", ErrInvalidKey)
	}
	out := jwsJSON{}
	var encodedPayload string
	for i, s := range signers {
		protectedB64, sigB64, enc, err := signOne(payload, s.Key, s.Options)
		if err != nil {
			return nil, fmt.Errorf("signature %d: %w", i, err)
		}
		if i == 0 {
			encodedPayload = enc
		} else if enc != encodedPayload {
			return nil, fmt.Errorf("%w: signers disagree on the payload encoding", ErrInvalidHeader)
		}
		if !s.Options.DetachPayload {
			out.Payload = encodedPayload
		}
		out.Signatures = append(out.Signatures, jwsSignature{
			Protected: protectedB64,
			Header:    copyHeaderOrNil(s.Options.Unprotected),
			Signature: sigB64,
		})
	}
	return json.Marshal(out)
}

// Verify checks the signature of a compact JWS and returns the payload and the
// protected header. The unsecured "none" algorithm is always rejected.
func Verify(token string, key any) (payload []byte, header map[string]any, err error) {
	return VerifyWithOptions(token, key, VerifyOptions{})
}

// VerifyWithOptions is Verify with explicit control over the accepted
// algorithms, the understood "crit" extensions, and a detached payload.
func VerifyWithOptions(token string, key any, opts VerifyOptions) (payload []byte, header map[string]any, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("%w: compact JWS must have 3 parts, got %d", ErrMalformed, len(parts))
	}
	protected, err := decodeHeader(parts[0])
	if err != nil {
		return nil, nil, err
	}
	payload, err = verifySignature(parts[0], protected, nil, parts[1], parts[2], key, opts)
	if err != nil {
		return nil, nil, err
	}
	return payload, protected, nil
}

// VerifyJSON checks a JWS in the general or flattened JSON serialization. It
// returns the payload and the merged protected and unprotected header of the
// first signature that verifies with key; if none does, it returns the last
// error encountered.
func VerifyJSON(data []byte, key any) (payload []byte, header map[string]any, err error) {
	return VerifyJSONWithOptions(data, key, VerifyOptions{})
}

// VerifyJSONWithOptions is VerifyJSON with explicit control over the accepted
// algorithms, the understood "crit" extensions, and a detached payload.
func VerifyJSONWithOptions(data []byte, key any, opts VerifyOptions) (payload []byte, header map[string]any, err error) {
	var doc jwsJSON
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	sigs := doc.Signatures
	if doc.Signature != "" {
		sigs = append(sigs, jwsSignature{
			Protected: doc.Protected,
			Header:    doc.Header,
			Signature: doc.Signature,
		})
	}
	if len(sigs) == 0 {
		return nil, nil, fmt.Errorf("%w: JWS JSON has no signatures", ErrMalformed)
	}

	lastErr := error(ErrSignatureInvalid)
	for _, s := range sigs {
		var protected map[string]any
		if s.Protected != "" {
			protected, err = decodeHeader(s.Protected)
			if err != nil {
				lastErr = err
				continue
			}
		}
		pl, err := verifySignature(s.Protected, protected, s.Header, doc.Payload, s.Signature, key, opts)
		if err != nil {
			lastErr = err
			continue
		}
		merged, err := mergeHeaders(protected, s.Header)
		if err != nil {
			lastErr = err
			continue
		}
		return pl, merged, nil
	}
	return nil, nil, lastErr
}

// --- internals ---

// signOne produces one signature, returning the encoded protected header, the
// encoded signature, and the payload as it will appear in the serialization.
func signOne(payload []byte, key any, opts SignOptions) (protectedB64, sigB64, encodedPayload string, err error) {
	resolved, err := resolveKey(key, opts.KeyID)
	if err != nil {
		return "", "", "", err
	}
	alg := opts.Algorithm
	if alg == "" {
		if jwk, ok := key.(*JWK); ok && jwk.Alg != "" {
			alg = jwk.Alg
		} else if alg, err = defaultSigAlg(resolved); err != nil {
			return "", "", "", err
		}
	}
	a, err := lookupSigAlg(alg)
	if err != nil {
		return "", "", "", err
	}

	protected := copyHeader(opts.Header)
	protected["alg"] = alg
	if opts.KeyID != "" {
		protected["kid"] = opts.KeyID
	} else if jwk, ok := key.(*JWK); ok && jwk.Kid != "" {
		// Carry the JWK's own key ID, but never where the caller has already
		// placed a "kid" of their own (a repeated header parameter is
		// forbidden by RFC 7515 §7.2.1).
		_, inProtected := protected["kid"]
		_, inUnprotected := opts.Unprotected["kid"]
		if !inProtected && !inUnprotected {
			protected["kid"] = jwk.Kid
		}
	}
	if len(opts.Critical) > 0 {
		protected["crit"] = opts.Critical
	}

	b64 := true
	if v, present := protected["b64"]; present {
		flag, ok := v.(bool)
		if !ok {
			return "", "", "", fmt.Errorf("%w: 'b64' must be a boolean", ErrInvalidHeader)
		}
		b64 = flag
		if !b64 && !containsString(opts.Critical, "b64") {
			return "", "", "", fmt.Errorf("%w: 'b64' must be listed in 'crit' when false", ErrInvalidCrit)
		}
	}
	if len(opts.Critical) > 0 {
		merged, err := mergeHeaders(protected, opts.Unprotected)
		if err != nil {
			return "", "", "", err
		}
		if err := checkCritical(protected, merged, opts.Critical); err != nil {
			return "", "", "", err
		}
	}

	protectedB64, err = encodeHeader(protected)
	if err != nil {
		return "", "", "", err
	}
	if b64 {
		encodedPayload = EncodeSegment(payload)
	} else {
		if strings.ContainsRune(string(payload), '.') {
			return "", "", "", fmt.Errorf("%w: an unencoded payload must not contain '.'", ErrInvalidToken)
		}
		encodedPayload = string(payload)
	}

	sig, err := a.sign(signingInput(protectedB64, encodedPayload), resolved)
	if err != nil {
		return "", "", "", err
	}
	return protectedB64, EncodeSegment(sig), encodedPayload, nil
}

// verifySignature validates one signature over the given payload segment.
// protectedSeg is the protected header exactly as it was received; the
// signature covers those octets, so it must never be re-serialized.
func verifySignature(protectedSeg string, protected, unprotected map[string]any, payloadSeg, sigSeg string, key any, opts VerifyOptions) ([]byte, error) {
	merged, err := mergeHeaders(protected, unprotected)
	if err != nil {
		return nil, err
	}
	alg := Header(merged).Algorithm()
	if alg == "" {
		return nil, fmt.Errorf("%w: missing 'alg'", ErrInvalidHeader)
	}
	if alg == None {
		return nil, ErrNoneAlgDisallowed
	}
	if len(opts.Algorithms) > 0 && !containsString(opts.Algorithms, alg) {
		return nil, fmt.Errorf("%w: alg %q is not accepted", ErrSignatureInvalid, alg)
	}
	known := append([]string{"b64"}, opts.KnownCritical...)
	if err := checkCritical(protected, merged, known); err != nil {
		return nil, err
	}

	b64 := true
	if v, present := merged["b64"]; present {
		flag, ok := v.(bool)
		if !ok {
			return nil, fmt.Errorf("%w: 'b64' must be a boolean", ErrInvalidHeader)
		}
		b64 = flag
	}

	if payloadSeg == "" {
		if len(opts.DetachedPayload) == 0 {
			return nil, ErrDetachedPayload
		}
		if b64 {
			payloadSeg = EncodeSegment(opts.DetachedPayload)
		} else {
			payloadSeg = string(opts.DetachedPayload)
		}
	}

	a, err := lookupSigAlg(alg)
	if err != nil {
		return nil, err
	}
	resolved, err := resolveKey(key, Header(merged).KeyID())
	if err != nil {
		return nil, err
	}
	sig, err := DecodeSegment(sigSeg)
	if err != nil {
		return nil, fmt.Errorf("%w: signature is not base64url: %v", ErrMalformed, err)
	}
	if err := a.verify(signingInput(protectedSeg, payloadSeg), sig, resolved); err != nil {
		return nil, err
	}

	if !b64 {
		return []byte(payloadSeg), nil
	}
	payload, err := DecodeSegment(payloadSeg)
	if err != nil {
		return nil, fmt.Errorf("%w: payload is not base64url: %v", ErrMalformed, err)
	}
	return payload, nil
}

// signingInput builds the JWS Signing Input, ASCII(protected) || '.' || payload.
func signingInput(protectedB64, payloadSeg string) []byte {
	buf := make([]byte, 0, len(protectedB64)+1+len(payloadSeg))
	buf = append(buf, protectedB64...)
	buf = append(buf, '.')
	buf = append(buf, payloadSeg...)
	return buf
}

// copyHeaderOrNil copies h, returning nil when h is empty so that the member is
// omitted from the JSON serialization.
func copyHeaderOrNil(h map[string]any) map[string]any {
	if len(h) == 0 {
		return nil
	}
	return copyHeader(h)
}
