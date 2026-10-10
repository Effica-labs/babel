package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestNewToken(t *testing.T) {
	a, err := NewToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(a) != 32 {
		t.Fatalf("token length = %d, want 32", len(a))
	}

	b, err := NewToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a == b {
		t.Fatal("tokens should be unique")
	}
}

func TestHashToken(t *testing.T) {
	h := HashToken("abc")
	if len(h) != 64 {
		t.Fatalf("hash length = %d, want 64", len(h))
	}
	if HashToken("abc") != h {
		t.Fatal("hash should be deterministic")
	}
	if HashToken("abd") == h {
		t.Fatal("different inputs should produce different hashes")
	}
}

func TestNewJWTAndParse(t *testing.T) {
	secret := []byte("secret")
	tok, err := NewJWT(secret, 42, "user@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	claims, err := ParseJWT(secret, tok)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.UserID != 42 {
		t.Fatalf("UserID = %d, want 42", claims.UserID)
	}
	if claims.Email != "user@example.com" {
		t.Fatalf("Email = %q, want user@example.com", claims.Email)
	}
	if claims.ID == "" {
		t.Fatal("missing jti")
	}
	if claims.ExpiresAt == nil {
		t.Fatal("missing expiry")
	}
	if d := time.Until(claims.ExpiresAt.Time); d < 23*time.Hour || d > 24*time.Hour {
		t.Fatalf("expiry duration = %v, want ~24h", d)
	}
}

func TestParseJWTRejectsWrongSecret(t *testing.T) {
	tok, err := NewJWT([]byte("secret"), 1, "a@b.c")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := ParseJWT([]byte("other"), tok); err == nil {
		t.Fatal("expected error for wrong secret")
	}
}

func TestParseJWTRejectsExpired(t *testing.T) {
	secret := []byte("secret")
	c := Claims{
		UserID: 1,
		Email:  "a@b.c",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(secret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := ParseJWT(secret, tok); err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestParseJWTRejectsGarbage(t *testing.T) {
	if _, err := ParseJWT([]byte("secret"), "not-a-jwt"); err == nil {
		t.Fatal("expected error for garbage token")
	}
}
