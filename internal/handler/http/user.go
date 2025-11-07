package http_handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/GroVlAn/auth-example/internal/core"
	"github.com/GroVlAn/auth-example/internal/core/e"
	"github.com/go-chi/chi"
)

const (
	registerEndpoint = "/register"
	userEndpoint     = "/user"
)

func (h *HTTPHandler) userRoute(r chi.Router) {
	r.Post(registerEndpoint, h.register)
	r.Get(userEndpoint, h.user)
}

func (h *HTTPHandler) register(w http.ResponseWriter, r *http.Request) {
	body := r.Body
	defer func(body io.ReadCloser) {
		if err := body.Close(); err != nil {
			h.l.Error().Err(err).Msg("failed to close request body")
		}
	}(body)

	var user core.User
	err := json.NewDecoder(body).Decode(&user)
	if err != nil {
		h.handleDecodeBody(w, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.defaultTimeout)
	defer cancel()

	err = h.userService.CreateUser(ctx, user)
	if err != nil {
		status, res := h.handleError(err)

		h.sendResponse(w, res, status)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("user created"))
}

func (h *HTTPHandler) user(w http.ResponseWriter, r *http.Request) {
	body := r.Body
	defer func(body io.ReadCloser) {
		if err := body.Close(); err != nil {
			h.l.Error().Err(err).Msg("failed to close request body")
		}
	}(body)

	var userReq core.UserRequest
	err := json.NewDecoder(body).Decode(&userReq)
	if err != nil {
		h.handleDecodeBody(w, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.defaultTimeout)
	defer cancel()

	user, err := h.userService.User(ctx, userReq)
	if err != nil {
		status, res := h.handleError(err)

		h.sendResponse(w, res, status)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(user)
	if err != nil {
		status, res := h.handleError(
			e.NewErrInternal(fmt.Errorf("failed to encode response body: %w", err)),
		)

		h.sendResponse(w, res, status)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("user fetched"))
}
