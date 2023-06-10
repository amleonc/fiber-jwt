package fiber_jwt

import (
	"strings"

	"github.com/gofiber/fiber/v2"
)

func fromCookie(name string) Extractor {
	return func(ctx *fiber.Ctx) string {
		return ctx.Cookies(name)
	}
}

func fromHeader(headerName, scheme string) Extractor {
	return func(ctx *fiber.Ctx) string {
		auth := ctx.Get(headerName)
		l := len(scheme)
		if len(auth) > l+1 && strings.EqualFold(auth[:l], scheme) {
			return strings.TrimSpace(auth[l:])
		}
		return ""
	}
}
