// Package auth implements console password hashing (argon2id, PHC string format).
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// Parameters of new hashes (RFC 9106 second recommendation, lighter memory).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 2
	argonKeyLen  = 32
	saltLen      = 16

	MinPasswordLen = 12
	MaxPasswordLen = 1024
)

var b64 = base64.RawStdEncoding

// HashPassword returns an argon2id PHC string for password.
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// ErrBadHash reports an unparsable stored hash.
var ErrBadHash = errors.New("empreinte de mot de passe illisible")

// VerifyPassword checks password against a PHC string in constant time.
func VerifyPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, ErrBadHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, ErrBadHash
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, ErrBadHash
	}
	// Refuse absurd parameters (a tampered row must not exhaust memory or CPU).
	if m < 8*1024 || m > 1024*1024 || t < 1 || t > 20 || p < 1 || p > 16 {
		return false, ErrBadHash
	}
	salt, err := b64.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return false, ErrBadHash
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil || len(want) < 16 || len(want) > 128 {
		return false, ErrBadHash
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// DummyHash returns a hash verified when the user does not exist, to equalize timings.
var DummyHash = sync.OnceValue(func() string {
	h, err := HashPassword("watchpost-dummy-password-for-timing")
	if err != nil {
		panic(err)
	}
	return h
})

// ValidUsername reports whether a console user name is acceptable.
func ValidUsername(u string) bool {
	if u == "" || len(u) > 64 {
		return false
	}
	for _, c := range u {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' || c == '@') {
			return false
		}
	}
	return true
}

// ValidPassword checks the password policy and returns a French message on failure.
func ValidPassword(p string) error {
	if len([]rune(p)) < MinPasswordLen {
		return fmt.Errorf("le mot de passe doit contenir au moins %d caractères", MinPasswordLen)
	}
	if len(p) > MaxPasswordLen {
		return fmt.Errorf("le mot de passe ne doit pas dépasser %d octets", MaxPasswordLen)
	}
	return nil
}
