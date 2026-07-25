package jose

import "encoding/base64"

// EncodeSegment returns the base64url (RFC 4648 §5) encoding of seg without
// padding, the encoding every JOSE serialization uses.
func EncodeSegment(seg []byte) string {
	return base64.RawURLEncoding.EncodeToString(seg)
}

// DecodeSegment decodes a base64url segment without padding. For robustness it
// also tolerates segments that carry '=' padding by falling back to the padded
// decoder, since some producers emit padding in violation of the spec.
func DecodeSegment(seg string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(seg); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(seg)
}
