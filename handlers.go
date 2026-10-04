package main

import (
	"crypto/subtle"
	"net/http"
	"net/mail"
	"net/url"
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
	q := c.QueryParams()
	switch {
	case q.Get("registered") == "1":
		message = "Registration complete. Check your email to confirm your account."
	case q.Get("confirmed") == "1":
		message = "Email confirmed. You can now log in."
	case q.Get("confirmed") == "error":
		message = "Invalid or expired confirmation link."
	case q.Get("password") == "1":
		message = "Password changed. Please log in again."
	case q.Get("reset") == "1":
		message = "Password reset. You can now log in."
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
	code, err := newCode()
	if err != nil {
		return render(c, http.StatusInternalServerError, "login.html", echo.Map{"Error": "Could not send verification code"})
	}
	_, err = db.Exec(`UPDATE users SET twofa_code = ?, twofa_expires = ? WHERE id = ?`, code, time.Now().Add(10*time.Minute).Unix(), id)
	if err != nil {
		return render(c, http.StatusInternalServerError, "login.html", echo.Map{"Error": "Could not send verification code"})
	}
	body := "Your babel verification code is: " + code + "\n\nIt expires in 10 minutes.\n"
	if err := sendEmail(email, "Your verification code", body); err != nil {
		c.Logger().Error(err)
		return render(c, http.StatusInternalServerError, "login.html", echo.Map{"Error": "Could not send verification email"})
	}
	return c.Redirect(http.StatusFound, "/verify?email="+url.QueryEscape(email))
}

func handleVerifyPage(c echo.Context) error {
	email := c.QueryParam("email")
	return render(c, http.StatusOK, "verify.html", echo.Map{"Email": email, "Error": ""})
}

func handleVerify(c echo.Context) error {
	email := c.FormValue("email")
	code := c.FormValue("code")
	if email == "" || code == "" {
		return render(c, http.StatusBadRequest, "verify.html", echo.Map{"Email": email, "Error": "Enter the code sent to your email"})
	}
	var id int64
	var stored string
	var exp int64
	err := db.QueryRow(`SELECT id, twofa_code, twofa_expires FROM users WHERE email = ?`, email).Scan(&id, &stored, &exp)
	if err != nil || stored == "" || time.Now().Unix() > exp || subtle.ConstantTimeCompare([]byte(stored), []byte(code)) != 1 {
		return render(c, http.StatusUnauthorized, "verify.html", echo.Map{"Email": email, "Error": "Invalid or expired code"})
	}
	_, _ = db.Exec(`UPDATE users SET twofa_code = '', twofa_expires = 0 WHERE id = ?`, id)
	token, err := newJWT(id, email)
	if err != nil {
		return render(c, http.StatusInternalServerError, "verify.html", echo.Map{"Email": email, "Error": "Could not start session"})
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

func handleForgotPage(c echo.Context) error {
	message := ""
	if c.QueryParam("sent") == "1" {
		message = "If an account exists for that email, a reset link has been sent."
	}
	return render(c, http.StatusOK, "forgot.html", echo.Map{"Message": message})
}

func handleForgot(c echo.Context) error {
	email := c.FormValue("email")
	var id int64
	var confirmed int
	err := db.QueryRow(`SELECT id, confirmed FROM users WHERE email = ?`, email).Scan(&id, &confirmed)
	if err == nil && confirmed == 1 {
		token, terr := newToken()
		if terr == nil {
			exp := time.Now().Add(1 * time.Hour).Unix()
			_, _ = db.Exec(`UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?`, token, exp, id)
			link := appURL() + "/reset?token=" + token
			body := "Reset your babel password by visiting:\n" + link + "\n\nIf you did not request this, ignore this email.\n"
			_ = sendEmail(email, "Reset your password", body)
		}
	}
	return c.Redirect(http.StatusFound, "/forgot?sent=1")
}

func handleResetPage(c echo.Context) error {
	token := c.QueryParam("token")
	errMsg := ""
	if token == "" {
		errMsg = "Invalid or expired reset link."
	} else {
		var one int
		if err := db.QueryRow(`SELECT 1 FROM users WHERE reset_token = ? AND reset_expires > ?`, token, time.Now().Unix()).Scan(&one); err != nil {
			errMsg = "Invalid or expired reset link."
		}
	}
	return render(c, http.StatusOK, "reset.html", echo.Map{"Token": token, "Error": errMsg})
}

func handleReset(c echo.Context) error {
	token := c.FormValue("token")
	password := c.FormValue("password")
	if token == "" {
		return render(c, http.StatusBadRequest, "reset.html", echo.Map{"Token": token, "Error": "Invalid or expired reset link."})
	}
	if len(password) < 8 {
		return render(c, http.StatusBadRequest, "reset.html", echo.Map{"Token": token, "Error": "Password must be at least 8 characters"})
	}
	hash, err := hashPassword(password)
	if err != nil {
		return render(c, http.StatusInternalServerError, "reset.html", echo.Map{"Token": token, "Error": "Could not reset password"})
	}
	res, err := db.Exec(`UPDATE users SET password_hash = ?, reset_token = '', reset_expires = 0 WHERE reset_token = ? AND reset_expires > ?`, hash, token, time.Now().Unix())
	if err != nil {
		return render(c, http.StatusInternalServerError, "reset.html", echo.Map{"Token": token, "Error": "Could not reset password"})
	}
	n, err := res.RowsAffected()
	if err != nil || n == 0 {
		return render(c, http.StatusBadRequest, "reset.html", echo.Map{"Token": token, "Error": "Invalid or expired reset link."})
	}
	return c.Redirect(http.StatusFound, "/login?reset=1")
}

func handleChangePassword(c echo.Context) error {
	token := c.Get("user").(*jwt.Token)
	cl := token.Claims.(*claims)
	current := c.FormValue("current_password")
	next := c.FormValue("new_password")
	var hash string
	err := db.QueryRow(`SELECT password_hash FROM users WHERE id = ?`, cl.UserID).Scan(&hash)
	if err != nil || !checkPassword(hash, current) {
		return render(c, http.StatusUnauthorized, "dashboard.html", echo.Map{"Email": cl.Email, "PasswordStatus": "Current password is incorrect"})
	}
	if len(next) < 8 {
		return render(c, http.StatusBadRequest, "dashboard.html", echo.Map{"Email": cl.Email, "PasswordStatus": "New password must be at least 8 characters"})
	}
	newHash, err := hashPassword(next)
	if err != nil {
		return render(c, http.StatusInternalServerError, "dashboard.html", echo.Map{"Email": cl.Email, "PasswordStatus": "Could not change password"})
	}
	_, err = db.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, newHash, cl.UserID)
	if err != nil {
		return render(c, http.StatusInternalServerError, "dashboard.html", echo.Map{"Email": cl.Email, "PasswordStatus": "Could not change password"})
	}
	cookie, cerr := c.Cookie(tokenCookie)
	if cerr == nil {
		revokeJWT(cookie.Value)
	}
	clearTokenCookie(c)
	return c.Redirect(http.StatusFound, "/login?password=1")
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
