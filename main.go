package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/time/rate"
)

var db *sql.DB

var cookieSecure bool

var jwtSecret []byte

type renderer struct {
	templates *template.Template
}

func (r *renderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return r.templates.ExecuteTemplate(w, name, data)
}

func loadSecret() []byte {
	if s := os.Getenv("BABEL_JWT_SECRET"); s != "" {
		return []byte(s)
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatal(err)
	}
	return b
}

func loadDotEnv(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if key != "" && os.Getenv(key) == "" {
			os.Setenv(key, val)
		}
	}
}

func main() {
	syscall.Umask(0o077)
	loadDotEnv(".env")
	cookieSecure = os.Getenv("BABEL_COOKIE_SECURE") == "true"
	jwtSecret = loadSecret()

	var err error
	db, err = openDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	e := echo.New()
	e.IPExtractor = echo.ExtractIPFromXFFHeader(echo.TrustLinkLocal(false), echo.TrustPrivateNet(false))
	e.Use(middleware.Logger())
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
		CookieSecure:   cookieSecure,
		CookieHTTPOnly: true,
		CookieSameSite: http.SameSiteStrictMode,
		ContextKey:     "csrf",
	}))
	e.Renderer = &renderer{templates: template.Must(template.ParseGlob("pages/*.html"))}

	loginLimiter := middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Store: middleware.NewRateLimiterMemoryStoreWithConfig(middleware.RateLimiterMemoryStoreConfig{
			Rate:      rate.Limit(10.0 / 60.0),
			Burst:     10,
			ExpiresIn: 3 * time.Minute,
		}),
		DenyHandler: func(c echo.Context, identifier string, err error) error {
			return render(c, http.StatusTooManyRequests, "login.html", echo.Map{"Error": "Too many attempts, please try again later"})
		},
	})
	registerLimiter := middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Store: middleware.NewRateLimiterMemoryStoreWithConfig(middleware.RateLimiterMemoryStoreConfig{
			Rate:      rate.Limit(5.0 / 60.0),
			Burst:     5,
			ExpiresIn: 3 * time.Minute,
		}),
		DenyHandler: func(c echo.Context, identifier string, err error) error {
			return render(c, http.StatusTooManyRequests, "register.html", echo.Map{"Error": "Too many attempts, please try again later"})
		},
	})

	jwtMiddleware := echojwt.WithConfig(echojwt.Config{
		SigningKey:  jwtSecret,
		TokenLookup: "cookie:token",
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(claims)
		},
		ErrorHandler: func(c echo.Context, err error) error {
			return c.Redirect(http.StatusFound, "/login")
		},
	})

	e.GET("/", handleIndex)
	e.GET("/login", handleLoginPage)
	e.POST("/login", handleLogin, loginLimiter)
	e.GET("/register", handleRegisterPage)
	e.POST("/register", handleRegister, registerLimiter)
	e.POST("/logout", handleLogout)
	forgotLimiter := middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Store: middleware.NewRateLimiterMemoryStoreWithConfig(middleware.RateLimiterMemoryStoreConfig{
			Rate:      rate.Limit(5.0 / 60.0),
			Burst:     5,
			ExpiresIn: 3 * time.Minute,
		}),
		DenyHandler: func(c echo.Context, identifier string, err error) error {
			return render(c, http.StatusTooManyRequests, "forgot.html", echo.Map{"Message": "Too many attempts, please try again later"})
		},
	})

	e.GET("/confirm", handleConfirm)
	e.GET("/forgot", handleForgotPage)
	e.POST("/forgot", handleForgot, forgotLimiter)
	e.GET("/reset", handleResetPage)
	e.POST("/reset", handleReset)
	e.GET("/dashboard", handleDashboard, jwtMiddleware, requireNotRevoked)
	e.POST("/change-password", handleChangePassword, jwtMiddleware, requireNotRevoked)

	go func() {
		if err := e.Start("127.0.0.1:8080"); err != nil && err != http.ErrServerClosed {
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
