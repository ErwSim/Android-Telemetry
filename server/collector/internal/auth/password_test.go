package auth

import (
	"strings"
	"testing"
)

func TestHashVerify(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("unexpected format %s", h)
	}
	if ok, err := VerifyPassword("correct horse battery staple", h); !ok || err != nil {
		t.Fatalf("verify: %v %v", ok, err)
	}
	if ok, _ := VerifyPassword("wrong", h); ok {
		t.Fatal("wrong password accepted")
	}
	h2, _ := HashPassword("correct horse battery staple")
	if h == h2 {
		t.Fatal("salt not random")
	}
}

func TestVerifyRejectsBadHashes(t *testing.T) {
	for _, h := range []string{"", "plain", "$argon2i$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=99999999,t=3,p=2$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=65536,t=3,p=2$!!$aGFzaGhhc2hoYXNoaGFzaA"} {
		if ok, err := VerifyPassword("x", h); ok || err == nil {
			t.Fatalf("bad hash %q accepted", h)
		}
	}
}

func TestPolicy(t *testing.T) {
	if ValidPassword("short") == nil || ValidPassword(strings.Repeat("a", 2000)) == nil || ValidPassword("long-enough-password") != nil {
		t.Fatal("password policy")
	}
	if !ValidUsername("admin") || ValidUsername("a b") || ValidUsername("") || ValidUsername("x'--") {
		t.Fatal("username policy")
	}
}
