package mailer

import "errors"

var ErrNotConfigured = errors.New("mailer: not configured")

type Mailer interface {
	Send(to, subject, body string) error
}
