package service

import (
	"errors"
	"strings"
	"testing"
	"time"

	"babel/internal/auth"
	"babel/internal/store"
)

type mockStore struct {
	userByEmailFunc         func(string) (store.User, error)
	userByIDFunc            func(int64) (store.User, error)
	createUserFunc          func(string) (int64, error)
	deleteUserFunc          func(int64) error
	setMagicTokenFunc       func(int64, string, int64) error
	hasActiveMagicTokenFunc func(int64, int64) (bool, error)
	consumeMagicTokenFunc   func(string, int64) (int64, error)
	tokenRevokedFunc        func(string, int64) (bool, error)
	revokeTokenFunc         func(string, int64) error
	closeFunc               func() error
}

func (m *mockStore) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

func (m *mockStore) UserByEmail(email string) (store.User, error) {
	if m.userByEmailFunc != nil {
		return m.userByEmailFunc(email)
	}
	return store.User{}, store.ErrNotFound
}

func (m *mockStore) UserByID(id int64) (store.User, error) {
	if m.userByIDFunc != nil {
		return m.userByIDFunc(id)
	}
	return store.User{}, store.ErrNotFound
}

func (m *mockStore) CreateUser(email string) (int64, error) {
	if m.createUserFunc != nil {
		return m.createUserFunc(email)
	}
	return 0, nil
}

func (m *mockStore) DeleteUser(id int64) error {
	if m.deleteUserFunc != nil {
		return m.deleteUserFunc(id)
	}
	return nil
}

func (m *mockStore) SetMagicToken(id int64, tokenHash string, expires int64) error {
	if m.setMagicTokenFunc != nil {
		return m.setMagicTokenFunc(id, tokenHash, expires)
	}
	return nil
}

func (m *mockStore) HasActiveMagicToken(id int64, now int64) (bool, error) {
	if m.hasActiveMagicTokenFunc != nil {
		return m.hasActiveMagicTokenFunc(id, now)
	}
	return false, nil
}

func (m *mockStore) ConsumeMagicToken(tokenHash string, now int64) (int64, error) {
	if m.consumeMagicTokenFunc != nil {
		return m.consumeMagicTokenFunc(tokenHash, now)
	}
	return 0, store.ErrNotFound
}

func (m *mockStore) TokenRevoked(jti string, now int64) (bool, error) {
	if m.tokenRevokedFunc != nil {
		return m.tokenRevokedFunc(jti, now)
	}
	return false, nil
}

func (m *mockStore) RevokeToken(jti string, expires int64) error {
	if m.revokeTokenFunc != nil {
		return m.revokeTokenFunc(jti, expires)
	}
	return nil
}

type mockMailer struct {
	sendFunc func(to, subject, body string) error
	to       []string
	subjects []string
	bodies   []string
}

func (m *mockMailer) Send(to, subject, body string) error {
	m.to = append(m.to, to)
	m.subjects = append(m.subjects, subject)
	m.bodies = append(m.bodies, body)
	if m.sendFunc != nil {
		return m.sendFunc(to, subject, body)
	}
	return nil
}

func newTestService(st store.Store, ml *mockMailer) *AuthService {
	return New(st, ml, []byte("secret"), "http://localhost")
}

func TestRequestLoginInvalidEmail(t *testing.T) {
	svc := newTestService(&mockStore{}, &mockMailer{})
	if err := svc.RequestLogin("not-an-email"); !errors.Is(err, ErrInvalidEmail) {
		t.Fatalf("expected ErrInvalidEmail, got %v", err)
	}
}

func TestRequestLoginNewUser(t *testing.T) {
	var gotID int64
	var gotHash string
	var gotExp int64
	st := &mockStore{
		userByEmailFunc: func(email string) (store.User, error) {
			return store.User{}, store.ErrNotFound
		},
		createUserFunc: func(email string) (int64, error) {
			return 7, nil
		},
		setMagicTokenFunc: func(id int64, tokenHash string, expires int64) error {
			gotID = id
			gotHash = tokenHash
			gotExp = expires
			return nil
		},
	}
	ml := &mockMailer{}
	svc := newTestService(st, ml)

	if err := svc.RequestLogin("user@example.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotID != 7 {
		t.Fatalf("stored token for id %d, want 7", gotID)
	}
	if len(gotHash) != 64 {
		t.Fatalf("stored token hash length = %d, want 64", len(gotHash))
	}
	if gotExp <= time.Now().Unix() {
		t.Fatal("stored token expiry should be in the future")
	}
	if len(ml.to) != 1 || ml.to[0] != "user@example.com" {
		t.Fatalf("unexpected recipients: %v", ml.to)
	}
	if !strings.Contains(ml.bodies[0], "/magic?token=") {
		t.Fatal("email body should contain magic link")
	}
}

func TestRequestLoginExistingUserWithActiveTokenDropsRequest(t *testing.T) {
	setCalled := false
	st := &mockStore{
		userByEmailFunc: func(email string) (store.User, error) {
			return store.User{ID: 7, Email: email}, nil
		},
		hasActiveMagicTokenFunc: func(id int64, now int64) (bool, error) {
			return true, nil
		},
		setMagicTokenFunc: func(id int64, tokenHash string, expires int64) error {
			setCalled = true
			return nil
		},
	}
	ml := &mockMailer{}
	svc := newTestService(st, ml)

	if err := svc.RequestLogin("user@example.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if setCalled {
		t.Fatal("should not set a new magic token when one is active")
	}
	if len(ml.to) != 0 {
		t.Fatalf("should not send email when token is active, got %v", ml.to)
	}
}

func TestRequestLoginExistingUserWithoutActiveToken(t *testing.T) {
	setCalled := false
	st := &mockStore{
		userByEmailFunc: func(email string) (store.User, error) {
			return store.User{ID: 7, Email: email}, nil
		},
		hasActiveMagicTokenFunc: func(id int64, now int64) (bool, error) {
			return false, nil
		},
		setMagicTokenFunc: func(id int64, tokenHash string, expires int64) error {
			setCalled = true
			return nil
		},
	}
	ml := &mockMailer{}
	svc := newTestService(st, ml)

	if err := svc.RequestLogin("user@example.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !setCalled {
		t.Fatal("should set a new magic token")
	}
	if len(ml.to) != 1 {
		t.Fatalf("should send one email, got %d", len(ml.to))
	}
}

func TestRequestLoginMailerErrorCleansUpUser(t *testing.T) {
	var deletedID int64
	st := &mockStore{
		userByEmailFunc: func(email string) (store.User, error) {
			return store.User{}, store.ErrNotFound
		},
		createUserFunc: func(email string) (int64, error) {
			return 7, nil
		},
		deleteUserFunc: func(id int64) error {
			deletedID = id
			return nil
		},
	}
	ml := &mockMailer{
		sendFunc: func(to, subject, body string) error {
			return errors.New("smtp down")
		},
	}
	svc := newTestService(st, ml)

	err := svc.RequestLogin("user@example.com")
	if !errors.Is(err, ErrSendEmail) {
		t.Fatalf("expected ErrSendEmail, got %v", err)
	}
	if deletedID != 7 {
		t.Fatalf("expected user 7 to be deleted, got %d", deletedID)
	}
}

func TestRequestLoginStoreError(t *testing.T) {
	st := &mockStore{
		userByEmailFunc: func(email string) (store.User, error) {
			return store.User{}, errors.New("db down")
		},
	}
	svc := newTestService(st, &mockMailer{})

	err := svc.RequestLogin("user@example.com")
	if !errors.Is(err, ErrInternal) {
		t.Fatalf("expected ErrInternal, got %v", err)
	}
}

func TestLoginWithMagicTokenEmpty(t *testing.T) {
	svc := newTestService(&mockStore{}, &mockMailer{})
	if _, err := svc.LoginWithMagicToken(""); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestLoginWithMagicTokenValid(t *testing.T) {
	var gotHash string
	st := &mockStore{
		consumeMagicTokenFunc: func(tokenHash string, now int64) (int64, error) {
			gotHash = tokenHash
			return 7, nil
		},
		userByIDFunc: func(id int64) (store.User, error) {
			return store.User{ID: 7, Email: "user@example.com"}, nil
		},
	}
	svc := newTestService(st, &mockMailer{})

	tok, err := svc.LoginWithMagicToken("rawtoken")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotHash != auth.HashToken("rawtoken") {
		t.Fatalf("consumed hash %q, want %q", gotHash, auth.HashToken("rawtoken"))
	}

	claims, err := auth.ParseJWT([]byte("secret"), tok)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if claims.UserID != 7 || claims.Email != "user@example.com" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestLoginWithMagicTokenInvalid(t *testing.T) {
	st := &mockStore{
		consumeMagicTokenFunc: func(tokenHash string, now int64) (int64, error) {
			return 0, store.ErrNotFound
		},
	}
	svc := newTestService(st, &mockMailer{})

	if _, err := svc.LoginWithMagicToken("bad"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestLoginWithMagicTokenStoreError(t *testing.T) {
	st := &mockStore{
		consumeMagicTokenFunc: func(tokenHash string, now int64) (int64, error) {
			return 0, errors.New("db down")
		},
	}
	svc := newTestService(st, &mockMailer{})

	if _, err := svc.LoginWithMagicToken("bad"); !errors.Is(err, ErrInternal) {
		t.Fatalf("expected ErrInternal, got %v", err)
	}
}

func TestLogoutRevokesJTI(t *testing.T) {
	tok, err := auth.NewJWT([]byte("secret"), 7, "user@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var gotJTI string
	st := &mockStore{
		revokeTokenFunc: func(jti string, expires int64) error {
			gotJTI = jti
			return nil
		},
	}
	svc := newTestService(st, &mockMailer{})

	svc.Logout(tok)
	if gotJTI == "" {
		t.Fatal("expected jti to be revoked")
	}
}

func TestLogoutInvalidTokenNoPanic(t *testing.T) {
	svc := newTestService(&mockStore{}, &mockMailer{})
	svc.Logout("not-a-jwt")
}
