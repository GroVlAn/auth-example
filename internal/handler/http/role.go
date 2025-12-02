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
	r.Post(createRoleEndpoint, h.createRole)
	r.Post(createPermissionEndpoint, h.createPermission)
	r.Get(permissionsEndpoint, h.permissions)

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
	roleName := chi.URLParam(r, "role_name")

	ctx, cancel := context.WithTimeout(r.Context(), h.DefaultTimeout)
	defer cancel()

	permissions, err := h.RoleService.Permissions(ctx, roleName)
	if err != nil {
		status, res := h.handleError(err)

		h.sendResponse(w, res, status)
		return
	}

	h.sendResponse(w, core.Response{Data: permissions}, http.StatusOK)
}
