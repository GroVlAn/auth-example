package http_handler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/GroVlAn/auth-example/internal/core"
	jwttoken "github.com/GroVlAn/auth-example/pkg/jwt-token"
	"github.com/go-chi/chi"
)

const (
	authEndpoint   = "/auth"
	verifyEndpoint = "/verify"
	updateEndpoint = "/update"
	logout         = "/logout"

	refreshCookieName = "refresh-token"
)

func (h *HTTPHandler) authRoute(r chi.Router) {
	r.With().Post(authEndpoint, h.auth)

	r.With(h.verifyAccToken).Post(verifyEndpoint, h.verifyAccessToken)

	r.With(h.verifyRefToken).Patch(updateEndpoint, h.updateAccessToken)

	r.With(
		h.verifyRefToken,
		h.verifyAccToken,
	).Delete(logout, h.logout)
}

func (h *HTTPHandler) auth(w http.ResponseWriter, r *http.Request) {
	h.withBodyClose(r.Body, func(body io.ReadCloser) {
		var authUser core.AuthUser

		if err := json.NewDecoder(body).Decode(&authUser); err != nil {
			h.handleDecodeBody(w, err)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), h.DefaultTimeout)
		defer cancel()

		rfToken, accToken, err := h.AuthService.Authenticate(ctx, authUser)
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
	})
}

func (h *HTTPHandler) verifyAccessToken(w http.ResponseWriter, r *http.Request) {
	res := core.Response{}
	res.Response = map[string]interface{}{
		"message": "token is valid",
	}

	h.sendResponse(w, res, http.StatusOK)
}

func (h *HTTPHandler) updateAccessToken(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.DefaultTimeout)
	defer cancel()

	refToken, ok := ctx.Value(core.RefreshTokenKey).(jwttoken.JWTDetails)
	if !ok {
		h.sendInternalError(w, "context does not store refresh token")
		return
	}

	newAccToken, err := h.AuthService.UpdateAccessToken(ctx, refToken)
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

func (h *HTTPHandler) logout(w http.ResponseWriter, r *http.Request) {
	action := chi.URLParam(r, "action")

	ctx, cancel := context.WithTimeout(r.Context(), h.DefaultTimeout)
	defer cancel()

	switch action {
	case "all":
		h.logoutAllDevices(ctx, w)
	case "current":
		h.logoutCurrentDevice(ctx, w)
	default:
		h.logoutCurrentDevice(ctx, w)
	}
}

func (h *HTTPHandler) logoutAllDevices(ctx context.Context, w http.ResponseWriter) {
	accToken, ok := ctx.Value(core.AccessTokenKey).(jwttoken.JWTDetails)
	if !ok {
		h.sendInternalError(w, "context does not store access token")
		return
	}

	err := h.AuthService.LogoutAllDevices(ctx, accToken)
	if err != nil {
		status, res := h.handleError(err)

		h.sendResponse(w, res, status)
		return
	}

	res := core.Response{}
	res.Response = map[string]interface{}{
		"message": "access tokens for all devices have been revoked",
	}

	h.sendResponse(w, res, http.StatusOK)
}

func (h *HTTPHandler) logoutCurrentDevice(ctx context.Context, w http.ResponseWriter) {
	refToken, ok := ctx.Value(core.RefreshTokenKey).(jwttoken.JWTDetails)
	if !ok {
		h.sendInternalError(w, "context does not store refresh token")
		return
	}

	accToken, ok := ctx.Value(core.AccessTokenKey).(jwttoken.JWTDetails)
	if !ok {
		h.sendInternalError(w, "context does not store access token")
		return
	}

	err := h.AuthService.Logout(ctx, refToken, accToken)
	if err != nil {
		status, res := h.handleError(err)

		h.sendResponse(w, res, status)
		return
	}

	res := core.Response{}
	res.Response = map[string]interface{}{
		"message": "access token for the current device has been revoked",
	}

	h.sendResponse(w, res, http.StatusOK)
}
