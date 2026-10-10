package service

import (
	"errors"
	"fmt"
	"net/mail"
	"time"

	"babel/internal/auth"
	"babel/internal/mailer"
	"babel/internal/store"
)

var (
	ErrInvalidEmail = errors.New("invalid email")
	ErrInvalidToken = errors.New("invalid or expired login link")
	ErrSendEmail    = errors.New("send email failed")
	ErrInternal     = errors.New("internal error")
)

type Service interface {
	RequestLogin(email string) error
	LoginWithMagicToken(token string) (string, error)
	Logout(tokenString string)
}

type AuthService struct {
	store  store.Store
	mailer mailer.Mailer
	secret []byte
	appURL string
}

func New(st store.Store, m mailer.Mailer, secret []byte, appURL string) *AuthService {
	return &AuthService{store: st, mailer: m, secret: secret, appURL: appURL}
}

func (s *AuthService) RequestLogin(email string) error {
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return ErrInvalidEmail
	}
	email = addr.Address

	user, err := s.store.UserByEmail(email)
	created := false
	if errors.Is(err, store.ErrNotFound) {
		id, cerr := s.store.CreateUser(email)
		if cerr != nil {
			return fmt.Errorf("%w: %v", ErrInternal, cerr)
		}
		user = store.User{ID: id}
		created = true
	} else if err != nil {
		return fmt.Errorf("%w: %v", ErrInternal, err)
	}

	token, err := auth.NewToken()
	if err != nil {
		if created {
			_ = s.store.DeleteUser(user.ID)
		}
		return fmt.Errorf("%w: %v", ErrInternal, err)
	}

	if err := s.store.SetMagicToken(user.ID, auth.HashToken(token), time.Now().Add(5*time.Minute).Unix()); err != nil {
		if created {
			_ = s.store.DeleteUser(user.ID)
		}
		return fmt.Errorf("%w: %v", ErrInternal, err)
	}

	link := s.appURL + "/magic?token=" + token
	body := "Log in to babel by visiting:\n" + link + "\n\nIf you did not request this, ignore this email.\n"
	if err := s.mailer.Send(email, "Your login link", body); err != nil {
		if created {
			_ = s.store.DeleteUser(user.ID)
		}
		return fmt.Errorf("%w: %v", ErrSendEmail, err)
	}

	return nil
}

func (s *AuthService) LoginWithMagicToken(token string) (string, error) {
	if token == "" {
		return "", ErrInvalidToken
	}

	id, err := s.store.ConsumeMagicToken(auth.HashToken(token), time.Now().Unix())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", ErrInvalidToken
		}
		return "", fmt.Errorf("%w: %v", ErrInternal, err)
	}

	user, err := s.store.UserByID(id)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInternal, err)
	}

	jwt, err := auth.NewJWT(s.secret, user.ID, user.Email)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInternal, err)
	}

	return jwt, nil
}

func (s *AuthService) Logout(tokenString string) {
	claims, err := auth.ParseJWT(s.secret, tokenString)
	if err != nil || claims.ID == "" {
		return
	}
	exp := time.Now().Add(24 * time.Hour).Unix()
	if claims.ExpiresAt != nil {
		exp = claims.ExpiresAt.Unix()
	}
	_ = s.store.RevokeToken(claims.ID, exp)
}
