package store

import (
	"database/sql"
	"errors"
	"os"
	"time"

	_ "modernc.org/sqlite"
)

const userColumns = "id, email, admin, confirmed, created_at"

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLite(path string) (*SQLiteStore, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(0)
	if err := ensureSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(row rowScanner) (User, error) {
	var u User
	var admin, confirmed int
	err := row.Scan(&u.ID, &u.Email, &admin, &confirmed, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	u.Admin = admin != 0
	u.Confirmed = confirmed != 0
	return u, nil
}

func (s *SQLiteStore) CreateUser(email string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO users (email, password_hash, confirmed) VALUES (?, '', 0)`, email)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *SQLiteStore) DeleteUser(id int64) error {
	_, err := s.db.Exec(`DELETE FROM users WHERE id = ?`, id)
	return err
}

func (s *SQLiteStore) UserByEmail(email string) (User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userColumns+` FROM users WHERE email = ?`, email))
}

func (s *SQLiteStore) UserByID(id int64) (User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userColumns+` FROM users WHERE id = ?`, id))
}

func (s *SQLiteStore) SetMagicToken(id int64, tokenHash string, expires int64) error {
	_, err := s.db.Exec(`UPDATE users SET magic_token = ?, magic_expires = ? WHERE id = ?`, tokenHash, expires, id)
	return err
}

func (s *SQLiteStore) ConsumeMagicToken(tokenHash string, now int64) (int64, error) {
	var id int64
	err := s.db.QueryRow(`UPDATE users SET confirmed = 1, magic_token = '', magic_expires = 0 WHERE magic_token = ? AND magic_expires > ? RETURNING id`, tokenHash, now).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (s *SQLiteStore) TokenRevoked(jti string, now int64) (bool, error) {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM revoked_tokens WHERE jti = ? AND expires_at > ?`, jti, now).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *SQLiteStore) RevokeToken(jti string, expires int64) error {
	if _, err := s.db.Exec(`DELETE FROM revoked_tokens WHERE expires_at <= ?`, time.Now().Unix()); err != nil {
		return err
	}
	_, err := s.db.Exec(`INSERT OR IGNORE INTO revoked_tokens (jti, expires_at) VALUES (?, ?)`, jti, expires)
	return err
}

func ensureSchema(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL DEFAULT '',
			admin INTEGER NOT NULL DEFAULT 0,
			confirmed INTEGER NOT NULL DEFAULT 0,
			magic_token TEXT NOT NULL DEFAULT '',
			magic_expires INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
		)`,
		`CREATE TABLE IF NOT EXISTS revoked_tokens (
			jti TEXT PRIMARY KEY,
			expires_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_users_magic_token ON users(magic_token)`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	cols := map[string]string{
		"admin":         "INTEGER NOT NULL DEFAULT 0",
		"confirmed":     "INTEGER NOT NULL DEFAULT 0",
		"magic_token":   "TEXT NOT NULL DEFAULT ''",
		"magic_expires": "INTEGER NOT NULL DEFAULT 0",
	}
	for col, def := range cols {
		if err := ensureColumn(db, col, def); err != nil {
			return err
		}
	}
	return nil
}

func ensureColumn(db *sql.DB, column, definition string) error {
	rows, err := db.Query(`PRAGMA table_info(users)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name string
		var ctype string
		var notnull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = db.Exec(`ALTER TABLE users ADD COLUMN ` + column + ` ` + definition)
	return err
}
