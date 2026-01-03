package http_handler

import (
	"context"
	"errors"
	"net/http"

	"github.com/GroVlAn/auth-example/internal/core"
	"github.com/GroVlAn/auth-example/internal/core/e"
	"github.com/go-chi/chi"
)

func (h *HTTPHandler) Cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")

		next.ServeHTTP(w, r)
	})
}

func (h *HTTPHandler) verifyRefToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		ctx, cancel := context.WithTimeout(r.Context(), h.DefaultTimeout)
		defer cancel()

		tokenDetails, err := h.AuthService.VerifyAccessToken(ctx, cookie.Value)
		if err != nil {
			status, res := h.handleError(err)

			h.sendResponse(w, res, status)
			return
		}

		ctx = context.WithValue(r.Context(), core.RefreshTokenKey, tokenDetails)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func (h *HTTPHandler) verifyAccToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accToken, err := h.extractBearerToken(r)
		if err != nil {
			status, res := h.handleError(err)

			h.sendResponse(w, res, status)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), h.DefaultTimeout)
		defer cancel()

		tokenDetails, err := h.AuthService.VerifyAccessToken(ctx, accToken)
		if err != nil {
			status, res := h.handleError(err)

			h.sendResponse(w, res, status)
			return
		}

		ctx = context.WithValue(r.Context(), core.AccessTokenKey, tokenDetails)

		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func (h *HTTPHandler) useMiddleware(r *chi.Mux) {
	r.Use(h.Cors)
}
