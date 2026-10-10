package mailer

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
)

type Config struct {
	Host     string
	Port     string
	User     string
	Password string
	From     string
	UseSSL   bool
	UseTLS   bool
}

type SMTP struct {
	config Config
}

func NewSMTP(config Config) *SMTP {
	return &SMTP{config: config}
}

func (m *SMTP) Send(to, subject, body string) error {
	c := m.config
	if c.Host == "" || c.Port == "" || c.User == "" || c.Password == "" || c.From == "" {
		return ErrNotConfigured
	}
	addr := net.JoinHostPort(c.Host, c.Port)

	var conn net.Conn
	var err error
	if c.UseSSL {
		conn, err = tls.Dial("tcp", addr, &tls.Config{ServerName: c.Host})
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		return err
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		return err
	}
	defer client.Close()

	if !c.UseSSL && c.UseTLS {
		if err := client.StartTLS(&tls.Config{ServerName: c.Host}); err != nil {
			return err
		}
	}

	if err := client.Auth(smtp.PlainAuth("", c.User, c.Password, c.Host)); err != nil {
		return err
	}
	if err := client.Mail(c.From); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s", c.From, to, subject, body)
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}
