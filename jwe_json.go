package jose

import (
	"encoding/json"
	"fmt"
)

// Recipient pairs a key with the key-management options used to encrypt the
// content encryption key for one recipient of a multi-recipient JWE.
type Recipient struct {
	// Key is the recipient's key: a Go crypto key, a []byte symmetric key or
	// PBES2 password, or a *JWK.
	Key any

	// Algorithm is the key management "alg" for this recipient. When empty
	// it is inferred from the key's type, or taken from the *JWK's "alg".
	Algorithm string

	// KeyID, when non-empty, identifies the key in this recipient's
	// unprotected header. A recipient-specific "kid" cannot live in the
	// protected header, which is shared by every recipient.
	KeyID string

	// Header holds additional per-recipient unprotected header parameters.
	// Algorithm outputs that differ per recipient ("epk", "iv", "tag",
	// "p2s", "p2c") are written here.
	Header map[string]any
}

// jweJSON is the general JWE JSON serialization (RFC 7516 §7.2.1). It also
// accepts the flattened form (§7.2.2) on decode.
type jweJSON struct {
	Protected   string         `json:"protected,omitempty"`
	Unprotected map[string]any `json:"unprotected,omitempty"`
	Recipients  []jweRecipient `json:"recipients,omitempty"`
	AAD         string         `json:"aad,omitempty"`
	IV          string         `json:"iv,omitempty"`
	Ciphertext  string         `json:"ciphertext"`
	Tag         string         `json:"tag,omitempty"`

	// Flattened form.
	Header       map[string]any `json:"header,omitempty"`
	EncryptedKey string         `json:"encrypted_key,omitempty"`
}

// jweRecipient is one entry of the "recipients" array.
type jweRecipient struct {
	Header       map[string]any `json:"header,omitempty"`
	EncryptedKey string         `json:"encrypted_key,omitempty"`
}

// EncryptJSON encrypts plaintext for a single recipient and returns the JWE
// general JSON serialization (RFC 7516 §7.2.1).
//
// Unlike the compact serialization, the JSON form can carry a shared
// unprotected header, per-recipient unprotected headers, and an "aad" member.
// Set EncryptOptions.AdditionalAuthenticatedData to use the last of these.
func EncryptJSON(plaintext []byte, key any, opts EncryptOptions) ([]byte, error) {
	return EncryptJSONMulti(plaintext, opts, Recipient{
		Key:       key,
		Algorithm: opts.Algorithm,
		KeyID:     opts.KeyID,
	})
}

// EncryptJSONMulti encrypts plaintext once and delivers the content encryption
// key to every recipient, returning the general JSON serialization.
//
// All recipients share one CEK and one content encryption, so the algorithms
// that derive the CEK rather than transport it — "dir" and direct "ECDH-ES" —
// may only be used with exactly one recipient.
func EncryptJSONMulti(plaintext []byte, opts EncryptOptions, recipients ...Recipient) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("%w: no recipients supplied", ErrInvalidKey)
	}
	encName := opts.Encryption
	if encName == "" {
		encName = A256GCM
	}
	enc, err := lookupEnc(encName)
	if err != nil {
		return nil, err
	}

	// The protected header is shared by every recipient, so it may only hold
	// parameters that do not vary between them.
	protected := copyHeader(opts.Header, opts.AdditionalHeaders)
	protected["enc"] = encName
	if opts.Compress {
		protected["zip"] = "DEF"
	}
	if opts.KeyID != "" && len(recipients) == 1 {
		protected["kid"] = opts.KeyID
	}

	var (
		cek []byte
		out = jweJSON{Unprotected: copyHeaderOrNil(opts.Unprotected)}
	)
	for i, r := range recipients {
		resolved, err := resolveKey(r.Key, r.KeyID)
		if err != nil {
			return nil, fmt.Errorf("recipient %d: %w", i, err)
		}
		alg := r.Algorithm
		if alg == "" {
			if jwk, ok := r.Key.(*JWK); ok && jwk.Alg != "" && keyMgmts[jwk.Alg].name != "" {
				alg = jwk.Alg
			} else if alg, err = defaultKeyMgmtAlg(resolved); err != nil {
				return nil, fmt.Errorf("recipient %d: %w", i, err)
			}
		}
		km, err := lookupKeyMgmt(alg)
		if err != nil {
			return nil, fmt.Errorf("recipient %d: %w", i, err)
		}
		if km.derivesCEK() && len(recipients) > 1 {
			return nil, fmt.Errorf("%w: %s cannot address %d recipients", ErrUnsupportedAlgorithm, alg, len(recipients))
		}

		// Algorithm inputs may be supplied per recipient; outputs are
		// written back to the same map.
		rh := copyHeader(r.Header)
		rh["alg"] = alg
		if r.KeyID != "" {
			rh["kid"] = r.KeyID
		} else if jwk, ok := r.Key.(*JWK); ok && jwk.Kid != "" {
			if _, present := rh["kid"]; !present {
				if _, inProtected := protected["kid"]; !inProtected {
					rh["kid"] = jwk.Kid
				}
			}
		}

		newCek, encryptedKey, err := km.encryptKey(enc, resolved, rh, cek)
		if err != nil {
			return nil, fmt.Errorf("recipient %d: %w", i, err)
		}
		cek = newCek

		if len(recipients) == 1 {
			// With a single recipient every parameter that does not need to
			// be per-recipient belongs in the protected header, where it is
			// covered by the authentication tag.
			for k, v := range rh {
				if _, dup := protected[k]; dup && k != "kid" {
					return nil, fmt.Errorf("%w: header parameter %q is repeated", ErrInvalidHeader, k)
				}
				protected[k] = v
			}
			out.Recipients = append(out.Recipients, jweRecipient{EncryptedKey: EncodeSegment(encryptedKey)})
		} else {
			out.Recipients = append(out.Recipients, jweRecipient{
				Header:       rh,
				EncryptedKey: EncodeSegment(encryptedKey),
			})
		}
	}

	body := plaintext
	if zip, _ := protected["zip"].(string); zip != "" {
		if zip != "DEF" {
			return nil, fmt.Errorf("%w: unsupported 'zip' %q", ErrInvalidHeader, zip)
		}
		if body, err = deflate(plaintext); err != nil {
			return nil, err
		}
	}

	protectedB64, err := encodeHeader(protected)
	if err != nil {
		return nil, err
	}
	aadB64 := ""
	if len(opts.AdditionalAuthenticatedData) > 0 {
		aadB64 = EncodeSegment(opts.AdditionalAuthenticatedData)
	}
	iv, ciphertext, tag, err := enc.encrypt(cek, body, jweAAD(protectedB64, aadB64))
	if err != nil {
		return nil, err
	}

	out.Protected = protectedB64
	out.AAD = aadB64
	out.IV = EncodeSegment(iv)
	out.Ciphertext = EncodeSegment(ciphertext)
	out.Tag = EncodeSegment(tag)
	return json.Marshal(out)
}

// DecryptJSON decrypts a JWE in the general or flattened JSON serialization and
// returns the plaintext and the merged header of the recipient that key
// unlocked.
func DecryptJSON(data []byte, key any) (plaintext []byte, header map[string]any, err error) {
	return DecryptJSONWithOptions(data, key, DecryptOptions{})
}

// DecryptJSONWithOptions is DecryptJSON with explicit control over the accepted
// algorithms, the understood "crit" extensions, and the decompression bound.
//
// When the document addresses several recipients, the one whose "kid" matches
// the supplied key is tried first; otherwise every recipient is tried in turn
// until one yields a content encryption key that authenticates the ciphertext.
func DecryptJSONWithOptions(data []byte, key any, opts DecryptOptions) (plaintext []byte, header map[string]any, err error) {
	var doc jweJSON
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	recipients := doc.Recipients
	if len(recipients) == 0 {
		// Flattened serialization: the single recipient's members are at the
		// top level.
		recipients = []jweRecipient{{Header: doc.Header, EncryptedKey: doc.EncryptedKey}}
	} else if doc.Header != nil || doc.EncryptedKey != "" {
		return nil, nil, fmt.Errorf("%w: a JWE cannot mix the general and flattened forms", ErrMalformed)
	}

	var protected map[string]any
	if doc.Protected != "" {
		if protected, err = decodeHeader(doc.Protected); err != nil {
			return nil, nil, err
		}
	}
	iv, err := decodeOptionalSegment("iv", doc.IV)
	if err != nil {
		return nil, nil, err
	}
	ciphertext, err := decodeOptionalSegment("ciphertext", doc.Ciphertext)
	if err != nil {
		return nil, nil, err
	}
	tag, err := decodeOptionalSegment("tag", doc.Tag)
	if err != nil {
		return nil, nil, err
	}
	if doc.AAD != "" {
		if _, err := DecodeSegment(doc.AAD); err != nil {
			return nil, nil, fmt.Errorf("%w: 'aad' is not base64url: %v", ErrMalformed, err)
		}
	}
	// RFC 7516 §5.1 step 14/15: with an "aad" member the additional
	// authenticated data is ASCII(protected || '.' || aad).
	aad := jweAAD(doc.Protected, doc.AAD)

	// Prefer the recipient whose kid matches the key, then fall back to
	// trial decryption of the rest.
	order := recipientOrder(recipients, protected, doc.Unprotected, key)

	lastErr := error(ErrDecryptFailed)
	for _, i := range order {
		r := recipients[i]
		merged, err := mergeHeaders(protected, doc.Unprotected, r.Header)
		if err != nil {
			lastErr = err
			continue
		}
		if err := checkCritical(protected, merged, opts.KnownCritical); err != nil {
			lastErr = err
			continue
		}
		encryptedKey, err := decodeOptionalSegment("encrypted_key", r.EncryptedKey)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := decryptOne(merged, encryptedKey, iv, ciphertext, tag, aad, key, opts)
		if err != nil {
			lastErr = err
			continue
		}
		return body, merged, nil
	}
	return nil, nil, lastErr
}

// decryptOne recovers the CEK for one recipient and decrypts the content.
func decryptOne(header map[string]any, encryptedKey, iv, ciphertext, tag, aad []byte, key any, opts DecryptOptions) ([]byte, error) {
	alg := Header(header).Algorithm()
	if alg == "" {
		return nil, fmt.Errorf("%w: missing 'alg'", ErrInvalidHeader)
	}
	if len(opts.Algorithms) > 0 && !containsString(opts.Algorithms, alg) {
		return nil, fmt.Errorf("%w: alg %q is not accepted", ErrDecryptFailed, alg)
	}
	encName := Header(header).Encryption()
	if encName == "" {
		return nil, fmt.Errorf("%w: missing 'enc'", ErrInvalidHeader)
	}
	if len(opts.Encryptions) > 0 && !containsString(opts.Encryptions, encName) {
		return nil, fmt.Errorf("%w: enc %q is not accepted", ErrDecryptFailed, encName)
	}
	km, err := lookupKeyMgmt(alg)
	if err != nil {
		return nil, err
	}
	enc, err := lookupEnc(encName)
	if err != nil {
		return nil, err
	}
	resolved, err := resolveKey(key, Header(header).KeyID())
	if err != nil {
		return nil, err
	}
	cek, err := km.decryptKey(enc, resolved, header, encryptedKey)
	if err != nil {
		return nil, err
	}
	if len(cek) != enc.keySize {
		return nil, ErrDecryptFailed
	}
	body, err := enc.decrypt(cek, iv, ciphertext, tag, aad)
	if err != nil {
		return nil, err
	}
	return maybeInflate(header, body, opts)
}

// maybeInflate applies the bounded "zip" decompression, if any.
func maybeInflate(header map[string]any, body []byte, opts DecryptOptions) ([]byte, error) {
	zip, ok := header["zip"]
	if !ok {
		return body, nil
	}
	name, ok := zip.(string)
	if !ok || name != "DEF" {
		return nil, fmt.Errorf("%w: unsupported 'zip' %v", ErrInvalidHeader, zip)
	}
	limit := opts.MaxDecompressed
	if limit <= 0 {
		limit = MaxDecompressedSize
	}
	return inflate(body, limit)
}

// jweAAD builds the additional authenticated data for content encryption: the
// encoded protected header, extended with "." and the encoded "aad" member when
// the JSON serialization carries one (RFC 7516 §5.1).
func jweAAD(protectedB64, aadB64 string) []byte {
	if aadB64 == "" {
		return []byte(protectedB64)
	}
	buf := make([]byte, 0, len(protectedB64)+1+len(aadB64))
	buf = append(buf, protectedB64...)
	buf = append(buf, '.')
	buf = append(buf, aadB64...)
	return buf
}

// decodeOptionalSegment decodes a possibly empty base64url member.
func decodeOptionalSegment(name, seg string) ([]byte, error) {
	if seg == "" {
		return nil, nil
	}
	b, err := DecodeSegment(seg)
	if err != nil {
		return nil, fmt.Errorf("%w: %q is not base64url: %v", ErrMalformed, name, err)
	}
	return b, nil
}

// recipientOrder returns the indices of recipients to try, putting any whose
// effective "kid" matches the supplied key first. Trying the matching
// recipient first turns the common case into a single key operation instead of
// a scan.
func recipientOrder(recipients []jweRecipient, protected, unprotected map[string]any, key any) []int {
	wantKid := ""
	switch k := key.(type) {
	case *JWK:
		if k != nil {
			wantKid = k.Kid
		}
	}
	if wantKid == "" {
		order := make([]int, len(recipients))
		for i := range order {
			order[i] = i
		}
		return order
	}
	var first, rest []int
	for i, r := range recipients {
		kid := ""
		for _, h := range []map[string]any{protected, unprotected, r.Header} {
			if s := Header(h).KeyID(); s != "" {
				kid = s
			}
		}
		if kid == wantKid {
			first = append(first, i)
		} else {
			rest = append(rest, i)
		}
	}
	return append(first, rest...)
}
