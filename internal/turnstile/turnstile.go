package turnstile

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"
)

const defaultVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

var ErrVerificationFailed = errors.New("turnstile: verification failed")

type Verifier struct {
	secret    string
	verifyURL string
	client    *http.Client
}

func New(secret string) *Verifier {
	return &Verifier{
		secret:    secret,
		verifyURL: defaultVerifyURL,
		client:    &http.Client{Timeout: 5 * time.Second},
	}
}

func (v *Verifier) Enabled() bool {
	return v != nil && v.secret != ""
}

type result struct {
	Success    bool     `json:"success"`
	Hostname   string   `json:"hostname"`
	ErrorCodes []string `json:"error-codes"`
}

func (v *Verifier) Verify(token, remoteIP string) (bool, error) {
	if !v.Enabled() {
		return true, nil
	}
	if token == "" {
		return false, ErrVerificationFailed
	}

	form := url.Values{}
	form.Set("secret", v.secret)
	form.Set("response", token)
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}

	resp, err := v.client.PostForm(v.verifyURL, form)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var res result
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return false, err
	}
	if !res.Success {
		return false, ErrVerificationFailed
	}
	return true, nil
}
