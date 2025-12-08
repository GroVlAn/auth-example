package http_handler

import (
	"errors"
	"net/http"
	"strings"

	"github.com/GroVlAn/auth-example/internal/core/e"
)

func (h *HTTPHandler) extractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", e.NewErrUnauthorized(
			errors.New("authorization header is missing"),
			"authorization header is missing",
		)
	}

	// Разделяем заголовок по пробелу
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", e.NewErrUnauthorized(
			errors.New("invalid authorization format"),
			"invalid authorization format",
		)
	}

	return parts[1], nil
}
