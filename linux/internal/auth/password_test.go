package auth

import (
	"strings"
	"testing"
)

func TestPasswordHashRoundTrip(t *testing.T) {
	password := []byte("correct horse battery staple")
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, password) {
		t.Fatal("valid password did not verify")
	}
	if VerifyPassword(hash, []byte("correct horse battery staplf")) {
		t.Fatal("incorrect password verified")
	}
	if VerifyPassword("$argon2id$invalid", password) {
		t.Fatal("malformed hash verified")
	}
}

func TestValidatePasswordHashRejectsMalformedOrUnsupportedHashes(t *testing.T) {
	password := []byte("correct horse battery staple")
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePasswordHash(hash); err != nil {
		t.Fatalf("valid hash rejected: %v", err)
	}
	for _, invalid := range []string{"", "$argon2id$invalid", strings.Replace(hash, "m=65536", "m=32768", 1)} {
		if err := ValidatePasswordHash(invalid); err == nil {
			t.Fatalf("invalid hash accepted: %q", invalid)
		}
	}
}

func TestPasswordPolicy(t *testing.T) {
	for _, password := range [][]byte{[]byte("short"), []byte("12345678901"), append([]byte("123456789012"), 0xff)} {
		if err := ValidatePortalPassword(password); err == nil {
			t.Fatalf("password %q unexpectedly passed", password)
		}
	}
	for _, password := range [][]byte{[]byte("123456789012"), []byte("界界界界界界界界界界界界")} {
		if err := ValidatePortalPassword(password); err != nil {
			t.Fatalf("valid 12-character password %q rejected: %v", password, err)
		}
	}
}

func TestRandomTokenEntropyLength(t *testing.T) {
	a, err := RandomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := RandomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	if a == b || len(a) != 43 || len(b) != 43 {
		t.Fatalf("unexpected random tokens: lengths %d, %d", len(a), len(b))
	}
}

func TestPortalUsernameGrammarIsStableForCLIAndAudit(t *testing.T) {
	for _, valid := range []string{"fixture9-portal", "Alice_2", "a"} {
		if err := ValidatePortalUsername(valid); err != nil {
			t.Fatalf("valid username %q rejected: %v", valid, err)
		}
	}
	for _, invalid := range []string{"", " has-space", "two words", "-leading", "用户"} {
		if err := ValidatePortalUsername(invalid); err == nil {
			t.Fatalf("invalid username %q accepted", invalid)
		}
	}
}
