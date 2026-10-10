package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	echomw "github.com/labstack/echo/v4/middleware"

	"babel/internal/service"
	"babel/internal/turnstile"
	"babel/internal/web"
)

type fakeService struct {
	requestLoginFunc        func(email string) error
	loginWithMagicTokenFunc func(token string) (string, error)
	logoutFunc              func(token string)
}

func (f *fakeService) RequestLogin(email string) error {
	if f.requestLoginFunc != nil {
		return f.requestLoginFunc(email)
	}
	return nil
}

func (f *fakeService) LoginWithMagicToken(token string) (string, error) {
	if f.loginWithMagicTokenFunc != nil {
		return f.loginWithMagicTokenFunc(token)
	}
	return "", service.ErrInvalidToken
}

func (f *fakeService) Logout(token string) {
	if f.logoutFunc != nil {
		f.logoutFunc(token)
	}
}

type fakeRevokedChecker struct{}

func (fakeRevokedChecker) TokenRevoked(jti string, now int64) (bool, error) {
	return false, nil
}

func newTestServer(t *testing.T, svc service.Service, ts *turnstile.Verifier, siteKey string) *echo.Echo {
	t.Helper()
	e := echo.New()
	e.Renderer = web.NewRenderer()
	e.Use(echomw.CSRFWithConfig(echomw.CSRFConfig{
		TokenLookup:    "form:_csrf",
		CookieName:     "_csrf",
		CookiePath:     "/",
		CookieSecure:   false,
		CookieHTTPOnly: true,
		CookieSameSite: http.SameSiteStrictMode,
		ContextKey:     "csrf",
	}))
	h := New(svc, []byte("secret"), fakeRevokedChecker{}, false, ts, siteKey)
	h.Register(e)
	return e
}

func doGet(t *testing.T, e *echo.Echo, path string) (*httptest.ResponseRecorder, []*http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec, rec.Result().Cookies()
}

func doPost(t *testing.T, e *echo.Echo, path string, cookies []*http.Cookie, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func extractCSRF(t *testing.T, body string) string {
	t.Helper()
	re := regexp.MustCompile(`name="_csrf" value="([^"]+)"`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no csrf token in response")
	}
	return m[1]
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestLoginPageRenders(t *testing.T) {
	e := newTestServer(t, &fakeService{}, turnstile.New(""), "")
	rec, _ := doGet(t, e, "/login")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Login") {
		t.Fatal("expected login page content")
	}
}

func TestLoginTurnstileDisabledSendsEmail(t *testing.T) {
	var gotEmail string
	svc := &fakeService{
		requestLoginFunc: func(email string) error {
			gotEmail = email
			return nil
		},
	}
	e := newTestServer(t, svc, turnstile.New(""), "")

	rec, cookies := doGet(t, e, "/login")
	csrf := extractCSRF(t, rec.Body.String())
	rec = doPost(t, e, "/login", cookies, url.Values{"_csrf": {csrf}, "email": {"user@example.com"}})

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login?sent=1" {
		t.Fatalf("location = %q, want /login?sent=1", loc)
	}
	if gotEmail != "user@example.com" {
		t.Fatalf("email = %q, want user@example.com", gotEmail)
	}
}

func TestLoginInvalidEmail(t *testing.T) {
	svc := &fakeService{
		requestLoginFunc: func(email string) error {
			return service.ErrInvalidEmail
		},
	}
	e := newTestServer(t, svc, turnstile.New(""), "")

	rec, cookies := doGet(t, e, "/login")
	csrf := extractCSRF(t, rec.Body.String())
	rec = doPost(t, e, "/login", cookies, url.Values{"_csrf": {csrf}, "email": {"bad"}})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Invalid email address") {
		t.Fatal("expected invalid email message")
	}
}

func TestLoginTurnstileEnabledMissingToken(t *testing.T) {
	svc := &fakeService{
		requestLoginFunc: func(email string) error {
			t.Fatal("should not send email without valid turnstile token")
			return nil
		},
	}
	e := newTestServer(t, svc, turnstile.New("secret"), "site-key")

	rec, cookies := doGet(t, e, "/login")
	csrf := extractCSRF(t, rec.Body.String())
	rec = doPost(t, e, "/login", cookies, url.Values{"_csrf": {csrf}, "email": {"user@example.com"}})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Captcha verification failed") {
		t.Fatal("expected captcha failure message")
	}
}

func TestMagicPageRenders(t *testing.T) {
	e := newTestServer(t, &fakeService{}, turnstile.New(""), "")
	rec, _ := doGet(t, e, "/magic?token=abc")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `id="magic-form"`) {
		t.Fatal("expected magic form")
	}
}

func TestMagicFlowSetsSession(t *testing.T) {
	svc := &fakeService{
		loginWithMagicTokenFunc: func(token string) (string, error) {
			if token != "abc" {
				return "", service.ErrInvalidToken
			}
			return "jwt-token", nil
		},
	}
	e := newTestServer(t, svc, turnstile.New(""), "")

	rec, cookies := doGet(t, e, "/magic?token=abc")
	csrf := extractCSRF(t, rec.Body.String())
	rec = doPost(t, e, "/magic", cookies, url.Values{"_csrf": {csrf}, "token": {"abc"}})

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Fatalf("location = %q, want /", loc)
	}

	cookie := findCookie(rec.Result().Cookies(), "token")
	if cookie == nil {
		t.Fatal("expected token cookie")
	}
	if cookie.Value != "jwt-token" {
		t.Fatalf("cookie value = %q, want jwt-token", cookie.Value)
	}
	if !cookie.HttpOnly {
		t.Fatal("expected HttpOnly cookie")
	}
}

func TestMagicFlowInvalidToken(t *testing.T) {
	svc := &fakeService{
		loginWithMagicTokenFunc: func(token string) (string, error) {
			return "", service.ErrInvalidToken
		},
	}
	e := newTestServer(t, svc, turnstile.New(""), "")

	rec, cookies := doGet(t, e, "/magic?token=bad")
	csrf := extractCSRF(t, rec.Body.String())
	rec = doPost(t, e, "/magic", cookies, url.Values{"_csrf": {csrf}, "token": {"bad"}})

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login?error=1" {
		t.Fatalf("location = %q, want /login?error=1", loc)
	}
}

func TestLogoutClearsSession(t *testing.T) {
	var gotToken string
	svc := &fakeService{
		logoutFunc: func(token string) {
			gotToken = token
		},
	}
	e := newTestServer(t, svc, turnstile.New(""), "")

	rec, cookies := doGet(t, e, "/login")
	csrf := extractCSRF(t, rec.Body.String())
	cookies = append(cookies, &http.Cookie{Name: "token", Value: "jwt-token"})
	rec = doPost(t, e, "/logout", cookies, url.Values{"_csrf": {csrf}})

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Fatalf("location = %q, want /login", loc)
	}
	if gotToken != "jwt-token" {
		t.Fatalf("logout token = %q, want jwt-token", gotToken)
	}

	cookie := findCookie(rec.Result().Cookies(), "token")
	if cookie == nil {
		t.Fatal("expected cleared token cookie")
	}
	if cookie.MaxAge >= 0 {
		t.Fatalf("expected negative MaxAge, got %d", cookie.MaxAge)
	}
}
