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
	message := ""
	switch c.QueryParam("registered") {
	case "1":
		message = "Registration complete. Check your email to confirm your account."
	}
	switch c.QueryParam("confirmed") {
	case "1":
		message = "Email confirmed. You can now log in."
	case "error":
		message = "Invalid or expired confirmation link."
	}
	return render(c, http.StatusOK, "login.html", echo.Map{"Error": "", "Message": message})
}

func handleLogin(c echo.Context) error {
	email := c.FormValue("email")
	password := c.FormValue("password")
	var id int64
	var hash string
	var confirmed int
	err := db.QueryRow(`SELECT id, password_hash, confirmed FROM users WHERE email = ?`, email).Scan(&id, &hash, &confirmed)
	if err != nil {
		checkPassword(dummyHash, password)
		return render(c, http.StatusUnauthorized, "login.html", echo.Map{"Error": "Invalid email or password"})
	}
	if !checkPassword(hash, password) {
		return render(c, http.StatusUnauthorized, "login.html", echo.Map{"Error": "Invalid email or password"})
	}
	if confirmed == 0 {
		return render(c, http.StatusUnauthorized, "login.html", echo.Map{"Error": "Please confirm your email address before logging in"})
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
	confirmToken, err := newToken()
	if err != nil {
		return render(c, http.StatusInternalServerError, "register.html", echo.Map{"Error": "Could not create account"})
	}
	res, err := db.Exec(`INSERT INTO users (email, password_hash, confirmed, confirm_token) VALUES (?, ?, 0, ?)`, email, hash, confirmToken)
	if err != nil {
		c.Logger().Error(err)
		return render(c, http.StatusInternalServerError, "register.html", echo.Map{"Error": "Could not create account"})
	}
	link := appURL() + "/confirm?token=" + confirmToken
	body := "Welcome to babel.\n\nConfirm your email address by visiting:\n" + link + "\n\nIf you did not create this account, you can ignore this email.\n"
	if err := sendEmail(email, "Confirm your email", body); err != nil {
		c.Logger().Error(err)
		if id, idErr := res.LastInsertId(); idErr == nil {
			_, _ = db.Exec(`DELETE FROM users WHERE id = ?`, id)
		}
		return render(c, http.StatusInternalServerError, "register.html", echo.Map{"Error": "Could not send confirmation email"})
	}
	return c.Redirect(http.StatusFound, "/login?registered=1")
}

func handleConfirm(c echo.Context) error {
	token := c.QueryParam("token")
	if token == "" {
		return c.Redirect(http.StatusFound, "/login?confirmed=error")
	}
	res, err := db.Exec(`UPDATE users SET confirmed = 1, confirm_token = '' WHERE confirm_token = ? AND confirmed = 0`, token)
	if err != nil {
		return c.Redirect(http.StatusFound, "/login?confirmed=error")
	}
	n, err := res.RowsAffected()
	if err != nil || n == 0 {
		return c.Redirect(http.StatusFound, "/login?confirmed=error")
	}
	return c.Redirect(http.StatusFound, "/login?confirmed=1")
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
