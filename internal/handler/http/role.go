package http_handler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/GroVlAn/auth-example/internal/core"
	"github.com/go-chi/chi"
)

const (
	createRoleEndpoint       = "/role/create"
	createPermissionEndpoint = "/role/permission/create"
	permissionsEndpoint      = "/role/permissions"
)

func (h *HTTPHandler) roleRoute(r chi.Router) {
	r.With(h.verifyPermission("admin_create")).Post(createRoleEndpoint, h.createRole)
	r.With(h.verifyPermission("admin_create")).Post(createPermissionEndpoint, h.createPermission)
	r.With(h.verifyPermission("user_watch")).Get(permissionsEndpoint, h.permissions)

}

func (h *HTTPHandler) createRole(w http.ResponseWriter, r *http.Request) {
	h.withBodyClose(r.Body, func(body io.ReadCloser) {
		var role core.Role
		if err := json.NewDecoder(body).Decode(&role); err != nil {
			h.handleDecodeBody(w, err)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), h.DefaultTimeout)
		defer cancel()

		if err := h.RoleService.CreateRole(ctx, role); err != nil {
			status, res := h.handleError(err)

			h.sendResponse(w, res, status)
			return
		}

		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("role created"))
	})
}

func (h *HTTPHandler) createPermission(w http.ResponseWriter, r *http.Request) {
	h.withBodyClose(r.Body, func(body io.ReadCloser) {
		var permReq core.PermissionRequest
		if err := json.NewDecoder(body).Decode(&permReq); err != nil {
			h.handleDecodeBody(w, err)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), h.DefaultTimeout)
		defer cancel()

		if err := h.RoleService.CreatePermission(ctx, permReq.Permission, permReq.RoleName); err != nil {
			status, res := h.handleError(err)

			h.sendResponse(w, res, status)
			return
		}

		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("permission created"))
	})
}

func (h *HTTPHandler) permissions(w http.ResponseWriter, r *http.Request) {
	roleID := chi.URLParam(r, "role_id")

	ctx, cancel := context.WithTimeout(r.Context(), h.DefaultTimeout)
	defer cancel()

	permissions, err := h.RoleService.Permissions(ctx, roleID)
	if err != nil {
		status, res := h.handleError(err)

		h.sendResponse(w, res, status)
		return
	}

	h.sendResponse(w, core.Response{Data: permissions}, http.StatusOK)
}
