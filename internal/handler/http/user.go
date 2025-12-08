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
	registerEndpoint       = "/user/register"
	userEndpoint           = "/user"
	setRoleEndpoint        = "/user/set-role"
	inactivateUserEndpoint = "/user/inactivate"
	restoreUserEndpoint    = "/user/restore"
	banUserEndpoint        = "/user/ban"
	unbanUserEndpoint      = "/user/unban"
)

func (h *HTTPHandler) userRoute(r chi.Router) {
	r.Post(registerEndpoint, h.register)

	r.With(h.verifyAccToken).
		Get(userEndpoint, h.user)

	r.With(h.verifyAccToken).
		Patch(setRoleEndpoint, h.setRole)

	r.With(h.verifyAccToken).
		Patch(inactivateUserEndpoint, h.inactivateUser)

	r.With(h.verifyAccToken).
		Patch(restoreUserEndpoint, h.restoreUser)

	r.With(h.verifyAccToken).
		Patch(banUserEndpoint, h.banUser)

	r.With(h.verifyAccToken).
		Patch(unbanUserEndpoint, h.unbanUser)
}

func (h *HTTPHandler) register(w http.ResponseWriter, r *http.Request) {
	h.withBodyClose(r.Body, func(body io.ReadCloser) {
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
	})
}

func (h *HTTPHandler) user(w http.ResponseWriter, r *http.Request) {
	h.withBodyClose(r.Body, func(body io.ReadCloser) {
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
	})
}

func (h *HTTPHandler) setRole(w http.ResponseWriter, r *http.Request) {
	h.withBodyClose(r.Body, func(body io.ReadCloser) {
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
	})
}

func (h *HTTPHandler) inactivateUser(w http.ResponseWriter, r *http.Request) {
	h.withBodyClose(r.Body, func(body io.ReadCloser) {
		h.changeUserStatus(w, r, body, "user inactivated", h.UserService.InactivateUser)
	})
}

func (h *HTTPHandler) restoreUser(w http.ResponseWriter, r *http.Request) {
	h.withBodyClose(r.Body, func(body io.ReadCloser) {
		h.changeUserStatus(w, r, body, "user restored", h.UserService.RestoreUser)
	})
}

func (h *HTTPHandler) banUser(w http.ResponseWriter, r *http.Request) {
	h.withBodyClose(r.Body, func(body io.ReadCloser) {
		h.changeUserStatus(w, r, body, "user banned", h.UserService.BanUser)
	})
}

func (h *HTTPHandler) unbanUser(w http.ResponseWriter, r *http.Request) {
	h.withBodyClose(r.Body, func(body io.ReadCloser) {
		h.changeUserStatus(w, r, body, "user unbanned", h.UserService.UnbanUser)
	})
}

func (h *HTTPHandler) changeUserStatus(
	w http.ResponseWriter,
	r *http.Request,
	body io.ReadCloser,
	successMessage string,
	fn func(context.Context, core.UserRequest) error,
) {
	var userReq core.UserRequest
	if err := json.NewDecoder(body).Decode(&userReq); err != nil {
		h.handleDecodeBody(w, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.DefaultTimeout)
	defer cancel()

	if err := fn(ctx, userReq); err != nil {
		status, res := h.handleError(err)

		h.sendResponse(w, res, status)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(successMessage))
}
