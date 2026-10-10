package web

import (
	"embed"
	"html/template"
	"io"

	"github.com/labstack/echo/v4"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static/*.js
var staticFS embed.FS

var templates = template.Must(template.ParseFS(templatesFS, "templates/*.html"))

type Renderer struct{}

func NewRenderer() *Renderer {
	return &Renderer{}
}

func (r *Renderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return templates.ExecuteTemplate(w, name, data)
}

func Render(c echo.Context, code int, name string, data echo.Map) error {
	if data == nil {
		data = echo.Map{}
	}
	data["csrf"] = c.Get("csrf")
	return c.Render(code, name, data)
}

func RegisterStatic(e *echo.Echo) {
	e.StaticFS("/static", echo.MustSubFS(staticFS, "static"))
}
