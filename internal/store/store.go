package store

import "errors"

var ErrNotFound = errors.New("store: not found")

type User struct {
	ID        int64
	Email     string
	Admin     bool
	Confirmed bool
	CreatedAt int64
}

type Store interface {
	Close() error
	UserByEmail(email string) (User, error)
	UserByID(id int64) (User, error)
	CreateUser(email string) (int64, error)
	DeleteUser(id int64) error
	SetMagicToken(id int64, tokenHash string, expires int64) error
	ConsumeMagicToken(tokenHash string, now int64) (int64, error)
	TokenRevoked(jti string, now int64) (bool, error)
	RevokeToken(jti string, expires int64) error
}
