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
	setRoleEndpoint  = "/set-role"
)

func (h *HTTPHandler) userRoute(r chi.Router) {
	r.Post(registerEndpoint, h.register)
	r.Get(userEndpoint, h.user)
	r.Patch(setRoleEndpoint, h.setRole)
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

	ctx, cancel := context.WithTimeout(r.Context(), h.DefaultTimeout)
	defer cancel()

	err = h.UserService.CreateUser(ctx, user)
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

	ctx, cancel := context.WithTimeout(r.Context(), h.DefaultTimeout)
	defer cancel()

	user, err := h.UserService.User(ctx, userReq)
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
}

func (h *HTTPHandler) setRole(w http.ResponseWriter, r *http.Request) {
	body := r.Body
	defer func(body io.ReadCloser) {
		if err := body.Close(); err != nil {
			h.l.Error().Err(err).Msg("failed to close request body")
		}
	}(body)

	var roleRequest core.RoleRequest
	if err := json.NewDecoder(body).Decode(&roleRequest); err != nil {
		h.handleDecodeBody(w, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.DefaultTimeout)
	defer cancel()

	if err := h.UserService.SetRole(ctx, roleRequest.UserID, roleRequest.RoleName); err != nil {
		status, res := h.handleError(err)

		h.sendResponse(w, res, status)
		return
	}

	w.WriteHeader(http.StatusOK)
}
