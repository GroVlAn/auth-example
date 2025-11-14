package http_handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/GroVlAn/auth-example/internal/core"
	"github.com/GroVlAn/auth-example/internal/core/e"
	"github.com/go-chi/chi"
)

const (
	authEndpoint   = "/auth"
	verifyEndpoint = "/verify"
	updateEndpoint = "/update"

	refreshCookieName = "refresh-token"
)

func (h *HTTPHandler) authRoute(r chi.Router) {
	r.Post(authEndpoint, h.auth)
	r.Post(verifyEndpoint, h.verifyAccessToken)
	r.Patch(updateEndpoint, h.updateAccessToken)
}

func (h *HTTPHandler) auth(w http.ResponseWriter, r *http.Request) {
	body := r.Body
	defer func(body io.ReadCloser) {
		if err := body.Close(); err != nil {
			h.l.Error().Err(err).Msg("failed to close request body")
		}
	}(body)

	var authUser core.AuthUser

	if err := json.NewDecoder(body).Decode(&authUser); err != nil {
		h.handleDecodeBody(w, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.DefaultTimeout)
	defer cancel()

	userAgent := r.Header.Get("User-Agent")

	rfToken, accToken, err := h.authService.Authenticate(ctx, authUser, userAgent)
	if err != nil {
		status, res := h.handleError(err)

		h.sendResponse(w, res, status)
		return
	}

	refreshTokenCookie := http.Cookie{
		Name:     refreshCookieName,
		Value:    rfToken.Token,
		Expires:  rfToken.EndTTL,
		MaxAge:   rfToken.EndTTL.Second(),
		HttpOnly: true,
		SameSite: http.SameSiteDefaultMode,
	}

	http.SetCookie(w, &refreshTokenCookie)

	res := core.Response{}
	res.Data = map[string]interface{}{
		"access_token": accToken.Token,
	}

	h.sendResponse(w, res, http.StatusOK)
}

func (h *HTTPHandler) verifyAccessToken(w http.ResponseWriter, r *http.Request) {
	accToken, err := h.extractBearerToken(r)
	if err != nil {
		status, res := h.handleError(err)

		h.sendResponse(w, res, status)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.DefaultTimeout)
	defer cancel()

	if err := h.authService.VerifyAccessToken(ctx, accToken); err != nil {
		status, res := h.handleError(err)

		h.sendResponse(w, res, status)
		return
	}

	res := core.Response{}
	res.Response = map[string]interface{}{
		"message": "token is valid",
	}

	h.sendResponse(w, res, http.StatusOK)
}

func (h *HTTPHandler) updateAccessToken(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(refreshCookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			status, res := h.handleError(e.NewErrUnauthorized(
				errors.New("authorization header is missing"),
				"authorization header is missing",
			))

			h.sendResponse(w, res, status)
			return
		}

		status, res := h.handleError(err)

		h.sendResponse(w, res, status)
		return
	}

	rfToken := cookie.Value

	ctx, cancel := context.WithTimeout(r.Context(), h.DefaultTimeout)
	defer cancel()

	newAccToken, err := h.authService.UpdateAccessToken(ctx, rfToken)
	if err != nil {
		status, res := h.handleError(err)

		h.sendResponse(w, res, status)
		return
	}

	res := core.Response{}
	res.Data = map[string]interface{}{
		"access_token": newAccToken.Token,
		"exp":          newAccToken.EndTTL.Unix(),
		"user_id":      newAccToken.UserID,
	}
	h.sendResponse(w, res, http.StatusOK)
}

func (h *HTTPHandler) extractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", e.NewErrUnauthorized(
			errors.New("authorization header is missing"),
			"authorization header is missing",
		)
	}

	fmt.Println("authHeader: ", authHeader)

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
