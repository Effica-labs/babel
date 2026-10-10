package middleware

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	echomw "github.com/labstack/echo/v4/middleware"
	"golang.org/x/time/rate"

	"babel/internal/web"
)

func LoginLimiter() echo.MiddlewareFunc {
	return echomw.RateLimiterWithConfig(echomw.RateLimiterConfig{
		Store: echomw.NewRateLimiterMemoryStoreWithConfig(echomw.RateLimiterMemoryStoreConfig{
			Rate:      rate.Limit(5.0 / 60.0),
			Burst:     5,
			ExpiresIn: 3 * time.Minute,
		}),
		DenyHandler: func(c echo.Context, identifier string, err error) error {
			return web.Render(c, http.StatusTooManyRequests, "login.html", echo.Map{"Error": "Too many attempts, please try again later"})
		},
	})
}
