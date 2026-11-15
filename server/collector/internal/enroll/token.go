package enroll

import "crypto/sha256"

// HashToken returns the stored form of a device token (SHA-256).
// Tokens carry 256 bits of entropy, so a fast hash is sufficient.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}
