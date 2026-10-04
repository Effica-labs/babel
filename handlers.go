package main

import (
	"net/http"
	"net/mail"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

const tokenCookie = "token"

func render(c echo.Context, code int, name string, data echo.Map) error {
	if data == nil {
		data = echo.Map{}
	}
	data["csrf"] = c.Get("csrf")
	return c.Render(code, name, data)
}

func setTokenCookie(c echo.Context, token string) {
	cookie := &http.Cookie{
		Name:     tokenCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   cookieSecure,
		Expires:  time.Now().Add(7 * 24 * time.Hour),
	}
	c.SetCookie(cookie)
}

func clearTokenCookie(c echo.Context) {
	cookie := &http.Cookie{
		Name:     tokenCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   cookieSecure,
		MaxAge:   -1,
	}
	c.SetCookie(cookie)
}

func handleIndex(c echo.Context) error {
	return c.Redirect(http.StatusFound, "/dashboard")
}

func handleLoginPage(c echo.Context) error {
	return render(c, http.StatusOK, "login.html", echo.Map{"Error": ""})
}

func handleLogin(c echo.Context) error {
	email := c.FormValue("email")
	password := c.FormValue("password")
	var id int64
	var hash string
	err := db.QueryRow(`SELECT id, password_hash FROM users WHERE email = ?`, email).Scan(&id, &hash)
	if err != nil {
		checkPassword(dummyHash, password)
		return render(c, http.StatusUnauthorized, "login.html", echo.Map{"Error": "Invalid email or password"})
	}
	if !checkPassword(hash, password) {
		return render(c, http.StatusUnauthorized, "login.html", echo.Map{"Error": "Invalid email or password"})
	}
	token, err := newJWT(id, email)
	if err != nil {
		return render(c, http.StatusInternalServerError, "login.html", echo.Map{"Error": "Could not start session"})
	}
	setTokenCookie(c, token)
	return c.Redirect(http.StatusFound, "/dashboard")
}

func handleRegisterPage(c echo.Context) error {
	return render(c, http.StatusOK, "register.html", echo.Map{"Error": ""})
}

func handleRegister(c echo.Context) error {
	email := c.FormValue("email")
	password := c.FormValue("password")
	if _, err := mail.ParseAddress(email); err != nil {
		return render(c, http.StatusBadRequest, "register.html", echo.Map{"Error": "Invalid email address"})
	}
	if len(password) < 8 {
		return render(c, http.StatusBadRequest, "register.html", echo.Map{"Error": "Password must be at least 8 characters"})
	}
	hash, err := hashPassword(password)
	if err != nil {
		return render(c, http.StatusInternalServerError, "register.html", echo.Map{"Error": "Could not create account"})
	}
	_, err = db.Exec(`INSERT INTO users (email, password_hash) VALUES (?, ?)`, email, hash)
	if err != nil {
		c.Logger().Error(err)
		return render(c, http.StatusInternalServerError, "register.html", echo.Map{"Error": "Could not create account"})
	}
	return c.Redirect(http.StatusFound, "/login")
}

func requireNotRevoked(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		token := c.Get("user").(*jwt.Token)
		cl := token.Claims.(*claims)
		var one int
		err := db.QueryRow(`SELECT 1 FROM revoked_tokens WHERE jti = ? AND expires_at > ?`, cl.ID, time.Now().Unix()).Scan(&one)
		if err == nil {
			return c.Redirect(http.StatusFound, "/login")
		}
		return next(c)
	}
}

func handleDashboard(c echo.Context) error {
	token := c.Get("user").(*jwt.Token)
	cl := token.Claims.(*claims)
	return render(c, http.StatusOK, "dashboard.html", echo.Map{"Email": cl.Email})
}

func handleLogout(c echo.Context) error {
	cookie, err := c.Cookie(tokenCookie)
	if err == nil {
		revokeJWT(cookie.Value)
	}
	clearTokenCookie(c)
	return c.Redirect(http.StatusFound, "/login")
}
