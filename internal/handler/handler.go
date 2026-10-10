package handler

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"babel/internal/middleware"
	"babel/internal/service"
)

const tokenCookie = "token"

type Handler struct {
	svc          service.Service
	secret       []byte
	revoked      middleware.RevokedChecker
	cookieSecure bool
}

func New(svc service.Service, secret []byte, revoked middleware.RevokedChecker, cookieSecure bool) *Handler {
	return &Handler{svc: svc, secret: secret, revoked: revoked, cookieSecure: cookieSecure}
}

func (h *Handler) Register(e *echo.Echo) {
	authMW := middleware.JWTAuth(h.secret, h.revoked)

	e.GET("/", h.handleDashboard, authMW)
	e.GET("/dashboard", h.handleDashboardRedirect, authMW)
	e.GET("/login", h.handleLoginPage)
	e.POST("/login", h.handleLogin, middleware.LoginLimiter())
	e.GET("/magic", h.handleMagic)
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
		Expires:  time.Now().Add(7 * 24 * time.Hour),
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
