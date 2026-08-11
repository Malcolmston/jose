package jose

import (
	"encoding/base64"
	"fmt"
)

// segmentEncoding is the only encoding a JOSE serialization may use: base64url
// (RFC 4648 §5) without padding, in strict mode.
//
// Strict mode matters for more than tidiness. Without it Go accepts a final
// quantum whose unused low bits are non-zero, so a 64-octet ECDSA signature has
// sixteen distinct base64url spellings that all decode to the same octets. Every
// one of them would verify, which makes the token string malleable — a problem
// for anything that keys a replay cache, an audit log, or a revocation list on
// the serialized token.
var segmentEncoding = base64.RawURLEncoding.Strict()

// EncodeSegment returns the base64url (RFC 4648 §5) encoding of seg without
// padding, the encoding every JOSE serialization uses.
func EncodeSegment(seg []byte) string {
	return segmentEncoding.EncodeToString(seg)
}

// DecodeSegment decodes a JOSE base64url segment.
//
// The decoding is strict and canonical: padding is rejected, as RFC 7515 §2
// requires ("base64url encoding ... with all trailing '=' characters omitted"),
// as are the standard-alphabet characters '+' and '/', embedded whitespace, and
// a final quantum with non-zero unused bits. Every valid input therefore has
// exactly one spelling, so DecodeSegment(EncodeSegment(b)) round-trips and no
// two distinct segments decode alike.
func DecodeSegment(seg string) ([]byte, error) {
	// encoding/base64 silently skips "\r" and "\n" wherever they appear, a
	// courtesy for MIME that has no place in a JOSE segment: it would give the
	// same value two spellings again. Screening the alphabet first also turns
	// '=' into a specific complaint instead of a generic one.
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_':
		case c == '=':
			return nil, fmt.Errorf("base64url: unexpected '=' padding at offset %d", i)
		default:
			return nil, fmt.Errorf("base64url: invalid character %q at offset %d", c, i)
		}
	}
	return segmentEncoding.DecodeString(seg)
}
