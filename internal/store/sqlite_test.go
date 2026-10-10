package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	st, err := NewSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Cleanup(func() {
		_ = st.Close()
	})
	return st
}

func TestCreateAndGetUser(t *testing.T) {
	st := newTestStore(t)

	id, err := st.CreateUser("a@b.c")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id == 0 {
		t.Fatal("expected non-zero id")
	}

	u, err := st.UserByEmail("a@b.c")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.ID != id || u.Email != "a@b.c" || u.Confirmed {
		t.Fatalf("unexpected user: %+v", u)
	}

	u2, err := st.UserByID(id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u2.Email != "a@b.c" {
		t.Fatalf("unexpected email: %q", u2.Email)
	}
}

func TestUserByEmailNotFound(t *testing.T) {
	st := newTestStore(t)
	if _, err := st.UserByEmail("missing@b.c"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestCreateUserDuplicateEmailFails(t *testing.T) {
	st := newTestStore(t)
	if _, err := st.CreateUser("dup@b.c"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := st.CreateUser("dup@b.c"); err == nil {
		t.Fatal("expected error for duplicate email")
	}
}

func TestDeleteUser(t *testing.T) {
	st := newTestStore(t)
	id, err := st.CreateUser("del@b.c")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := st.DeleteUser(id); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := st.UserByEmail("del@b.c"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestMagicTokenLifecycle(t *testing.T) {
	st := newTestStore(t)
	id, err := st.CreateUser("magic@b.c")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	now := time.Now().Unix()
	if err := st.SetMagicToken(id, "hash1", now+300); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	active, err := st.HasActiveMagicToken(id, now+1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !active {
		t.Fatal("expected active token")
	}

	active, err = st.HasActiveMagicToken(id, now+301)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if active {
		t.Fatal("expected expired token to be inactive")
	}

	gotID, err := st.ConsumeMagicToken("hash1", now+1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotID != id {
		t.Fatalf("consumed id = %d, want %d", gotID, id)
	}

	u, err := st.UserByID(id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !u.Confirmed {
		t.Fatal("expected user to be confirmed after magic link")
	}

	if _, err := st.ConsumeMagicToken("hash1", now+1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for single-use token, got %v", err)
	}
}

func TestConsumeExpiredMagicToken(t *testing.T) {
	st := newTestStore(t)
	id, err := st.CreateUser("exp@b.c")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	now := time.Now().Unix()
	if err := st.SetMagicToken(id, "hash2", now+300); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := st.ConsumeMagicToken("hash2", now+301); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for expired token, got %v", err)
	}
}

func TestRevokedTokens(t *testing.T) {
	st := newTestStore(t)
	now := time.Now().Unix()

	if err := st.RevokeToken("jti-1", now+3600); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	revoked, err := st.TokenRevoked("jti-1", now+1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !revoked {
		t.Fatal("expected token to be revoked")
	}

	revoked, err = st.TokenRevoked("jti-1", now+3601)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if revoked {
		t.Fatal("expected revocation to expire")
	}

	revoked, err = st.TokenRevoked("missing-jti", now+1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if revoked {
		t.Fatal("expected missing token to not be revoked")
	}
}

func TestRevokeTokenCleansExpired(t *testing.T) {
	st := newTestStore(t)
	now := time.Now().Unix()

	if err := st.RevokeToken("expired", now-10); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := st.RevokeToken("fresh", now+3600); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	revoked, err := st.TokenRevoked("expired", time.Now().Unix())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if revoked {
		t.Fatal("expected expired revocation to be cleaned up")
	}

	revoked, err = st.TokenRevoked("fresh", time.Now().Unix())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !revoked {
		t.Fatal("expected fresh revocation to remain")
	}
}
