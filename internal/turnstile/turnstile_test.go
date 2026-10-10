package turnstile

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVerifierEnabled(t *testing.T) {
	if New("").Enabled() {
		t.Fatal("empty secret should be disabled")
	}
	if !New("secret").Enabled() {
		t.Fatal("non-empty secret should be enabled")
	}
}

func TestVerifyDisabled(t *testing.T) {
	v := New("")
	ok, err := v.Verify("", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("disabled verifier should allow")
	}
}

func TestVerifyEmptyTokenWhenEnabled(t *testing.T) {
	v := New("secret")
	ok, err := v.Verify("", "1.2.3.4")
	if err != ErrVerificationFailed {
		t.Fatalf("expected ErrVerificationFailed, got %v", err)
	}
	if ok {
		t.Fatal("empty token should fail")
	}
}

func TestVerifySuccess(t *testing.T) {
	var gotSecret, gotResponse, gotRemoteIP string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotSecret = r.Form.Get("secret")
		gotResponse = r.Form.Get("response")
		gotRemoteIP = r.Form.Get("remoteip")
		_ = json.NewEncoder(w).Encode(result{Success: true, Hostname: "example.com"})
	}))
	defer srv.Close()

	v := New("secret")
	v.verifyURL = srv.URL

	ok, err := v.Verify("token", "1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected success")
	}
	if gotSecret != "secret" || gotResponse != "token" || gotRemoteIP != "1.2.3.4" {
		t.Fatalf("unexpected form values: secret=%q response=%q remoteip=%q", gotSecret, gotResponse, gotRemoteIP)
	}
}

func TestVerifyFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(result{Success: false})
	}))
	defer srv.Close()

	v := New("secret")
	v.verifyURL = srv.URL

	ok, err := v.Verify("token", "")
	if err != ErrVerificationFailed {
		t.Fatalf("expected ErrVerificationFailed, got %v", err)
	}
	if ok {
		t.Fatal("expected failure")
	}
}

func TestVerifyBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	v := New("secret")
	v.verifyURL = srv.URL

	ok, err := v.Verify("token", "")
	if err == nil {
		t.Fatal("expected JSON decode error")
	}
	if ok {
		t.Fatal("expected failure")
	}
}

func TestVerifyRequestError(t *testing.T) {
	v := New("secret")
	v.verifyURL = "http://127.0.0.1:1"
	if _, err := v.Verify("token", ""); err == nil {
		t.Fatal("expected request error")
	}
}

func TestVerifyContentType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
			t.Errorf("unexpected content type: %s", ct)
		}
		_ = json.NewEncoder(w).Encode(result{Success: true})
	}))
	defer srv.Close()

	v := New("secret")
	v.verifyURL = srv.URL
	if _, err := v.Verify("token", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
