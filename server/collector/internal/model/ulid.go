package model

import (
	"crypto/rand"
	"time"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewULID returns a ULID for time t with 80 bits of cryptographic randomness
// (identifiers of events produced by the collector itself).
func NewULID(t time.Time) string {
	var b [16]byte
	ms := uint64(t.UnixMilli())
	for i := 5; i >= 0; i-- {
		b[i] = byte(ms)
		ms >>= 8
	}
	_, _ = rand.Read(b[6:])
	return EncodeULID(b)
}

// EncodeULID renders 128 bits as 26 Crockford base32 characters.
func EncodeULID(b [16]byte) string {
	var out [26]byte
	var acc uint64
	bits := 0
	idx := 25
	for i := 15; i >= 0; i-- {
		acc |= uint64(b[i]) << bits
		bits += 8
		for bits >= 5 && idx > 0 {
			out[idx] = crockford[acc&31]
			acc >>= 5
			bits -= 5
			idx--
		}
	}
	out[0] = crockford[acc&31]
	return string(out[:])
}

// ValidULID reports whether s is a canonical (upper-case) ULID.
func ValidULID(s string) bool { return ulidRe.MatchString(s) }
