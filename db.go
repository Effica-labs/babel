package main

import (
	"database/sql"
	"os"

	_ "modernc.org/sqlite"
)

func openDB() (*sql.DB, error) {
	path := os.Getenv("BABEL_DB")
	if path == "" {
		path = "babel.db"
	}
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(0)
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	return db, nil
}

func migrate(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			admin INTEGER NOT NULL DEFAULT 0,
			confirmed INTEGER NOT NULL DEFAULT 0,
			confirm_token TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
		)`,
		`CREATE TABLE IF NOT EXISTS revoked_tokens (
			jti TEXT PRIMARY KEY,
			expires_at INTEGER NOT NULL
		)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return err
		}
	}
	cols := map[string]string{
		"admin":         "INTEGER NOT NULL DEFAULT 0",
		"confirmed":     "INTEGER NOT NULL DEFAULT 1",
		"confirm_token": "TEXT NOT NULL DEFAULT ''",
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
