package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	"babel/internal/auth"
)

type stubRevokedChecker struct {
	revoked bool
	err     error
}

func (s stubRevokedChecker) TokenRevoked(jti string, now int64) (bool, error) {
	return s.revoked, s.err
}

func runAuthMiddleware(t *testing.T, secret []byte, checker RevokedChecker, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	e := echo.New()
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	}, JWTAuth(secret, checker))

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func TestJWTAuthValidToken(t *testing.T) {
	secret := []byte("secret")
	tok, err := auth.NewJWT(secret, 1, "user@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "token", Value: tok})

	rec := runAuthMiddleware(t, secret, stubRevokedChecker{}, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "ok" {
		t.Fatalf("body = %q, want ok", rec.Body.String())
	}
}

func TestJWTAuthMissingToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := runAuthMiddleware(t, []byte("secret"), stubRevokedChecker{}, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Fatalf("location = %q, want /login", loc)
	}
}

func TestJWTAuthInvalidToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "token", Value: "bad"})
	rec := runAuthMiddleware(t, []byte("secret"), stubRevokedChecker{}, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
}

func TestJWTAuthRevokedToken(t *testing.T) {
	secret := []byte("secret")
	tok, err := auth.NewJWT(secret, 1, "user@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "token", Value: tok})

	rec := runAuthMiddleware(t, secret, stubRevokedChecker{revoked: true}, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Fatalf("location = %q, want /login", loc)
	}
}

func TestJWTAuthRevocationCheckErrorFailsClosed(t *testing.T) {
	secret := []byte("secret")
	tok, err := auth.NewJWT(secret, 1, "user@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "token", Value: tok})

	rec := runAuthMiddleware(t, secret, stubRevokedChecker{err: errors.New("db down")}, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 on revocation check error", rec.Code)
	}
}
