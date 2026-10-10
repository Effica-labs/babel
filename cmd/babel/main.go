package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"babel/internal/config"
	"babel/internal/handler"
	"babel/internal/mailer"
	"babel/internal/service"
	"babel/internal/store"
	"babel/internal/web"
)

func main() {
	syscall.Umask(0o077)
	cfg := config.Load()

	st, err := store.NewSQLite(cfg.DBPath)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	mlr := mailer.NewSMTP(cfg.SMTP)
	svc := service.New(st, mlr, cfg.JWTSecret, cfg.AppURL)
	h := handler.New(svc, cfg.JWTSecret, st, cfg.CookieSecure)

	e := echo.New()
	e.IPExtractor = echo.ExtractIPFromXFFHeader(echo.TrustLinkLocal(false), echo.TrustPrivateNet(false))
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: `{"time":"${time_rfc3339_nano}","id":"${id}","remote_ip":"${remote_ip}",` +
			`"host":"${host}","method":"${method}","path":"${path}","user_agent":"${user_agent}",` +
			`"status":${status},"error":"${error}","latency":${latency},"latency_human":"${latency_human}"` +
			`,"bytes_in":${bytes_in},"bytes_out":${bytes_out}}` + "\n",
	}))
	e.Use(middleware.Recover())
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		ContentTypeNosniff:    "nosniff",
		XFrameOptions:         "DENY",
		ReferrerPolicy:        "same-origin",
		ContentSecurityPolicy: "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
	}))
	e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
		TokenLookup:    "form:_csrf",
		CookieName:     "_csrf",
		CookiePath:     "/",
		CookieSecure:   cfg.CookieSecure,
		CookieHTTPOnly: true,
		CookieSameSite: http.SameSiteStrictMode,
		ContextKey:     "csrf",
	}))
	e.Renderer = web.NewRenderer()

	h.Register(e)

	go func() {
		if err := e.Start(cfg.Addr); err != nil && err != http.ErrServerClosed {
			e.Logger.Fatal(err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.Shutdown(ctx); err != nil {
		e.Logger.Fatal(err)
	}
}
