package config

import (
	"crypto/rand"
	"log"
	"os"
	"strings"

	"babel/internal/mailer"
)

type Config struct {
	Addr             string
	DBPath           string
	CookieSecure     bool
	JWTSecret        []byte
	AppURL           string
	SMTP             mailer.Config
	TurnstileSiteKey string
	TurnstileSecret  string
}

func Load() Config {
	loadDotEnv(".env")

	secret := os.Getenv("BABEL_JWT_SECRET")
	if secret == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			log.Fatal(err)
		}
		secret = string(b)
	}

	return Config{
		Addr:         envOr("BABEL_ADDR", "127.0.0.1:8080"),
		DBPath:       envOr("BABEL_DB", "babel.db"),
		CookieSecure: os.Getenv("BABEL_COOKIE_SECURE") == "true",
		JWTSecret:    []byte(secret),
		AppURL:       strings.TrimSuffix(envOr("APP_URL", "http://localhost:8080"), "/"),
		SMTP: mailer.Config{
			Host:     os.Getenv("SMTP_HOST"),
			Port:     os.Getenv("SMTP_PORT"),
			User:     os.Getenv("SMTP_USER"),
			Password: os.Getenv("SMTP_PASSWORD"),
			From:     os.Getenv("SMTP_FROM"),
			UseSSL:   strings.EqualFold(os.Getenv("SMTP_USE_SSL"), "true"),
			UseTLS:   strings.EqualFold(os.Getenv("SMTP_USE_TLS"), "true"),
		},
		TurnstileSiteKey: os.Getenv("TURNSTILE_SITE_KEY"),
		TurnstileSecret:  os.Getenv("TURNSTILE_SITE_SECRET"),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func loadDotEnv(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if key != "" && os.Getenv(key) == "" {
			os.Setenv(key, val)
		}
	}
}
