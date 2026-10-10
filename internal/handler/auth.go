package handler

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"

	"babel/internal/service"
	"babel/internal/web"
)

func (h *Handler) handleLoginPage(c echo.Context) error {
	message := ""
	switch {
	case c.QueryParam("sent") == "1":
		message = "Check your email. We sent you a login link."
	case c.QueryParam("error") == "1":
		message = "Invalid or expired login link."
	}
	return web.Render(c, http.StatusOK, "login", echo.Map{"Title": "Login", "Error": "", "Message": message, "SiteKey": h.turnstileSiteKey})
}

func (h *Handler) handleLogin(c echo.Context) error {
	email := c.FormValue("email")

	if h.turnstileEnabled() {
		ok, err := h.turnstile.Verify(c.FormValue("cf-turnstile-response"), c.RealIP())
		if err != nil {
			c.Logger().Error(err)
		}
		if err != nil || !ok {
			return web.Render(c, http.StatusBadRequest, "login", echo.Map{"Title": "Login", "Error": "Captcha verification failed. Please try again.", "SiteKey": h.turnstileSiteKey})
		}
	}

	err := h.svc.RequestLogin(email)
	switch {
	case errors.Is(err, service.ErrInvalidEmail):
		return web.Render(c, http.StatusBadRequest, "login", echo.Map{"Title": "Login", "Error": "Invalid email address", "SiteKey": h.turnstileSiteKey})
	case errors.Is(err, service.ErrSendEmail):
		c.Logger().Error(err)
		return web.Render(c, http.StatusInternalServerError, "login", echo.Map{"Title": "Login", "Error": "Could not send login email", "SiteKey": h.turnstileSiteKey})
	case err != nil:
		c.Logger().Error(err)
		return web.Render(c, http.StatusInternalServerError, "login", echo.Map{"Title": "Login", "Error": "Could not send login email", "SiteKey": h.turnstileSiteKey})
	}
	return c.Redirect(http.StatusFound, "/login?sent=1")
}

func (h *Handler) handleMagicPage(c echo.Context) error {
	token := c.QueryParam("token")
	if token == "" {
		return c.Redirect(http.StatusFound, "/login?error=1")
	}
	return web.Render(c, http.StatusOK, "magic", echo.Map{"Title": "Login", "Token": token})
}

func (h *Handler) handleMagic(c echo.Context) error {
	token := c.FormValue("token")
	jwt, err := h.svc.LoginWithMagicToken(token)
	if err != nil {
		c.Logger().Error(err)
		return c.Redirect(http.StatusFound, "/login?error=1")
	}
	h.setTokenCookie(c, jwt)
	return c.Redirect(http.StatusFound, "/")
}

func (h *Handler) handleRegisterRedirect(c echo.Context) error {
	return c.Redirect(http.StatusFound, "/login")
}
