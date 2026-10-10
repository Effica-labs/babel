package middleware

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"

	"babel/internal/auth"
)

type RevokedChecker interface {
	TokenRevoked(jti string, now int64) (bool, error)
}

func JWTAuth(secret []byte, checker RevokedChecker) echo.MiddlewareFunc {
	jwtMW := echojwt.WithConfig(echojwt.Config{
		SigningKey:  secret,
		TokenLookup: "cookie:token",
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return &auth.Claims{}
		},
		ErrorHandler: func(c echo.Context, err error) error {
			return c.Redirect(http.StatusFound, "/login")
		},
	})

	revokeMW := func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			token := c.Get("user").(*jwt.Token)
			cl := token.Claims.(*auth.Claims)
			revoked, err := checker.TokenRevoked(cl.ID, time.Now().Unix())
			if err != nil {
				c.Logger().Error(err)
				return c.Redirect(http.StatusFound, "/login")
			}
			if revoked {
				return c.Redirect(http.StatusFound, "/login")
			}
			return next(c)
		}
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return jwtMW(revokeMW(next))
	}
}
