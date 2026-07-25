package jose

import (
	"encoding/json"
	"fmt"
)

// Header is a decoded JOSE header. Sign, Verify, Encrypt, and Decrypt exchange
// headers as plain map[string]any values; this named type exists so the helper
// accessors have somewhere to live.
type Header map[string]any

// String returns the value of a string-valued header parameter, or "" if the
// parameter is absent or not a string.
func (h Header) String(name string) string {
	s, _ := h[name].(string)
	return s
}

// Algorithm returns the "alg" header parameter.
func (h Header) Algorithm() string { return h.String("alg") }

// Encryption returns the "enc" header parameter.
func (h Header) Encryption() string { return h.String("enc") }

// KeyID returns the "kid" header parameter.
func (h Header) KeyID() string { return h.String("kid") }

// Type returns the "typ" header parameter.
func (h Header) Type() string { return h.String("typ") }

// ContentType returns the "cty" header parameter.
func (h Header) ContentType() string { return h.String("cty") }

// Critical returns the "crit" header parameter as a list of extension names.
// The second result is false if "crit" is absent or is not an array of strings.
func (h Header) Critical() ([]string, bool) {
	raw, ok := h["crit"]
	if !ok {
		return nil, false
	}
	switch list := raw.(type) {
	case []string:
		// A header built in Go rather than decoded from JSON.
		return append([]string(nil), list...), true
	case []any:
		out := make([]string, 0, len(list))
		for _, v := range list {
			s, ok := v.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	default:
		return nil, false
	}
}

// decodeHeader parses a base64url-encoded protected header into a map.
func decodeHeader(seg string) (map[string]any, error) {
	raw, err := DecodeSegment(seg)
	if err != nil {
		return nil, fmt.Errorf("%w: protected header is not base64url: %v", ErrMalformed, err)
	}
	var h map[string]any
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, fmt.Errorf("%w: protected header is not JSON: %v", ErrMalformed, err)
	}
	if h == nil {
		return nil, fmt.Errorf("%w: protected header is null", ErrMalformed)
	}
	return h, nil
}

// encodeHeader serializes a header as compact JSON and base64url-encodes it.
func encodeHeader(h map[string]any) (string, error) {
	raw, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("%w: cannot serialize header: %v", ErrInvalidHeader, err)
	}
	return EncodeSegment(raw), nil
}

// copyHeader returns a shallow copy of h, or an empty map if h is nil.
func copyHeader(hs ...map[string]any) map[string]any {
	out := make(map[string]any)
	for _, h := range hs {
		for k, v := range h {
			out[k] = v
		}
	}
	return out
}

// mergeHeaders combines protected and unprotected headers into the single view
// returned to callers, rejecting any parameter that appears in more than one of
// them (RFC 7515 §7.2.1 and RFC 7516 §7.2.1 require member names to be
// disjoint).
func mergeHeaders(hs ...map[string]any) (map[string]any, error) {
	out := make(map[string]any)
	for _, h := range hs {
		for k, v := range h {
			if _, dup := out[k]; dup {
				return nil, fmt.Errorf("%w: header parameter %q is repeated", ErrInvalidHeader, k)
			}
			out[k] = v
		}
	}
	return out, nil
}

// checkCritical enforces RFC 7515 §4.1.11: every name listed in "crit" must be
// a parameter the recipient understands and that is actually present in the
// protected header. known holds the extension names the caller has declared as
// understood.
func checkCritical(protected, merged map[string]any, known []string) error {
	crit, ok := Header(protected).Critical()
	if _, present := protected["crit"]; present && !ok {
		return fmt.Errorf("%w: 'crit' must be an array of strings", ErrInvalidCrit)
	}
	if !ok {
		return nil
	}
	if len(crit) == 0 {
		return fmt.Errorf("%w: 'crit' must not be empty", ErrInvalidCrit)
	}
	for _, name := range crit {
		if name == "" {
			return fmt.Errorf("%w: 'crit' contains an empty name", ErrInvalidCrit)
		}
		if isRegisteredHeader(name) {
			return fmt.Errorf("%w: 'crit' must not list the registered parameter %q", ErrInvalidCrit, name)
		}
		if _, present := merged[name]; !present {
			return fmt.Errorf("%w: critical parameter %q is not present", ErrInvalidCrit, name)
		}
		if !containsString(known, name) {
			return fmt.Errorf("%w: critical parameter %q is not understood", ErrInvalidCrit, name)
		}
	}
	return nil
}

// registeredHeaders are the JOSE header parameters defined by RFC 7515 and
// RFC 7516; RFC 7515 §4.1.11 forbids listing any of them in "crit".
var registeredHeaders = map[string]bool{
	"alg": true, "jku": true, "jwk": true, "kid": true, "x5u": true,
	"x5c": true, "x5t": true, "x5t#S256": true, "typ": true, "cty": true,
	"crit": true, "enc": true, "zip": true, "epk": true, "apu": true,
	"apv": true, "iv": true, "tag": true, "p2s": true, "p2c": true,
}

// isRegisteredHeader reports whether name is a registered JOSE header
// parameter.
func isRegisteredHeader(name string) bool { return registeredHeaders[name] }

// containsString reports whether list contains s.
func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// resolveKey unwraps a *JWK or JWKSet into the Go crypto key the algorithms
// operate on, and passes any other key type through unchanged. kid, when
// non-empty, selects the key from a set.
func resolveKey(key any, kid string) (any, error) {
	switch k := key.(type) {
	case *JWK:
		if k == nil {
			return nil, fmt.Errorf("%w: nil JWK", ErrInvalidKey)
		}
		return k.Key()
	case *JWKSet:
		if k == nil {
			return nil, fmt.Errorf("%w: nil JWK set", ErrInvalidKey)
		}
		if kid == "" && len(k.Keys) == 1 {
			return k.Keys[0].Key()
		}
		jwk, ok := k.LookupKeyID(kid)
		if !ok {
			return nil, fmt.Errorf("%w: kid %q", ErrKeyNotFound, kid)
		}
		return jwk.Key()
	case nil:
		return nil, fmt.Errorf("%w: no key supplied", ErrInvalidKey)
	default:
		return key, nil
	}
}
