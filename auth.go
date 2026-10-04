package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type claims struct {
	UserID int64  `json:"uid"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

var dummyHash = func() string {
	h, err := bcrypt.GenerateFromPassword([]byte("dummy-password"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return string(h)
}()

func hashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func checkPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func newToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func newCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func newJWT(userID int64, email string) (string, error) {
	jti, err := newToken()
	if err != nil {
		return "", err
	}
	now := time.Now()
	c := claims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			ExpiresAt: jwt.NewNumericDate(now.Add(7 * 24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(jwtSecret)
}

func revokeJWT(tokenString string) {
	token, err := jwt.ParseWithClaims(tokenString, new(claims), func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return
	}
	cl, ok := token.Claims.(*claims)
	if !ok || cl.ID == "" {
		return
	}
	exp := time.Now().Add(24 * time.Hour).Unix()
	if cl.ExpiresAt != nil {
		exp = cl.ExpiresAt.Unix()
	}
	_, _ = db.Exec(`DELETE FROM revoked_tokens WHERE expires_at <= ?`, time.Now().Unix())
	_, _ = db.Exec(`INSERT OR IGNORE INTO revoked_tokens (jti, expires_at) VALUES (?, ?)`, cl.ID, exp)
}
