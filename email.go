package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strings"
)

func appURL() string {
	u := os.Getenv("APP_URL")
	if u == "" {
		u = "http://localhost:8080"
	}
	return strings.TrimSuffix(u, "/")
}

func sendEmail(to, subject, body string) error {
	host := os.Getenv("SMTP_HOST")
	port := os.Getenv("SMTP_PORT")
	user := os.Getenv("SMTP_USER")
	password := os.Getenv("SMTP_PASSWORD")
	from := os.Getenv("SMTP_FROM")
	if host == "" || port == "" || user == "" || password == "" || from == "" {
		return fmt.Errorf("smtp configuration is incomplete")
	}
	addr := net.JoinHostPort(host, port)
	useSSL := strings.EqualFold(os.Getenv("SMTP_USE_SSL"), "true")
	useTLS := strings.EqualFold(os.Getenv("SMTP_USE_TLS"), "true")

	var conn net.Conn
	var err error
	if useSSL {
		conn, err = tls.Dial("tcp", addr, &tls.Config{ServerName: host})
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		return err
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer client.Close()

	if !useSSL && useTLS {
		if err := client.StartTLS(&tls.Config{ServerName: host}); err != nil {
			return err
		}
	}

	if err := client.Auth(smtp.PlainAuth("", user, password, host)); err != nil {
		return err
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s", from, to, subject, body)
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}
