package handler

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"

	"babel/internal/auth"
	"babel/internal/web"
)

func (h *Handler) handleIndex(c echo.Context) error {
	return c.Redirect(http.StatusFound, "/dashboard")
}

func (h *Handler) handleDashboard(c echo.Context) error {
	token := c.Get("user").(*jwt.Token)
	cl := token.Claims.(*auth.Claims)
	return web.Render(c, http.StatusOK, "dashboard.html", echo.Map{"Email": cl.Email})
}

func (h *Handler) handleLogout(c echo.Context) error {
	cookie, err := c.Cookie(tokenCookie)
	if err == nil {
		h.svc.Logout(cookie.Value)
	}
	h.clearTokenCookie(c)
	return c.Redirect(http.StatusFound, "/login")
}
