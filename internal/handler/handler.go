package handler

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"babel/internal/middleware"
	"babel/internal/service"
	"babel/internal/turnstile"
)

const tokenCookie = "token"

type Handler struct {
	svc              service.Service
	secret           []byte
	revoked          middleware.RevokedChecker
	cookieSecure     bool
	turnstile        *turnstile.Verifier
	turnstileSiteKey string
}

func New(svc service.Service, secret []byte, revoked middleware.RevokedChecker, cookieSecure bool, ts *turnstile.Verifier, siteKey string) *Handler {
	return &Handler{svc: svc, secret: secret, revoked: revoked, cookieSecure: cookieSecure, turnstile: ts, turnstileSiteKey: siteKey}
}

func (h *Handler) turnstileEnabled() bool {
	return h.turnstile != nil && h.turnstile.Enabled() && h.turnstileSiteKey != ""
}

func (h *Handler) Register(e *echo.Echo) {
	authMW := middleware.JWTAuth(h.secret, h.revoked)

	e.GET("/", h.handleDashboard, authMW)
	e.GET("/dashboard", h.handleDashboardRedirect, authMW)
	e.GET("/login", h.handleLoginPage)
	e.POST("/login", h.handleLogin, middleware.LoginLimiter(h.turnstileSiteKey))
	e.GET("/magic", h.handleMagicPage)
	e.POST("/magic", h.handleMagic)
	e.GET("/register", h.handleRegisterRedirect)
	e.POST("/logout", h.handleLogout)
}

func (h *Handler) setTokenCookie(c echo.Context, token string) {
	cookie := &http.Cookie{
		Name:     tokenCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.cookieSecure,
		Expires:  time.Now().Add(24 * time.Hour),
	}
	c.SetCookie(cookie)
}

func (h *Handler) clearTokenCookie(c echo.Context) {
	cookie := &http.Cookie{
		Name:     tokenCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.cookieSecure,
		MaxAge:   -1,
	}
	c.SetCookie(cookie)
}
