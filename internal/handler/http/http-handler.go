package http_handler

import (
	"context"
	"net/http"
	"time"

	"github.com/GroVlAn/auth-example/internal/core"
	jwttoken "github.com/GroVlAn/auth-example/pkg/jwt-token"
	"github.com/go-chi/chi"
	"github.com/rs/zerolog"
)

type authenticator interface {
	Authenticate(ctx context.Context, authUser core.AuthUser) (core.RefreshToken, core.AccessToken, error)
	UpdateAccessToken(ctx context.Context, refToken jwttoken.JWTDetails) (core.AccessToken, error)
	VerifyAccessToken(ctx context.Context, accToken string) (jwttoken.JWTDetails, error)
	VerifyRefreshToken(ctx context.Context, rfToken string) (jwttoken.JWTDetails, error)
	Logout(ctx context.Context, refToken, accToken jwttoken.JWTDetails) error
	LogoutAllDevices(ctx context.Context, accToken jwttoken.JWTDetails) error
}

type userService interface {
	CreateUser(ctx context.Context, user core.User) error
	User(ctx context.Context, userReq core.UserRequest) (core.User, error)
	SetRole(ctx context.Context, userID string, roleName string) error
	InactivateUser(ctx context.Context, userReq core.UserRequest) error
	RestoreUser(ctx context.Context, userReq core.UserRequest) error
	BanUser(ctx context.Context, userReq core.UserRequest) error
	UnbanUser(ctx context.Context, userReq core.UserRequest) error
}

type roleService interface {
	CreateRole(ctx context.Context, role core.Role) error
	CreatePermission(ctx context.Context, permission core.Permission, roleName string) error
	Permissions(ctx context.Context, roleName string) ([]core.Permission, error)
	VerifyPermission(ctx context.Context, accToken jwttoken.JWTDetails, permission string) (bool, error)
}

type Deps struct {
	BasePath       string
	DefaultTimeout time.Duration
}

type Services struct {
	UserService userService
	AuthService authenticator
	RoleService roleService
}

type HTTPHandler struct {
	l zerolog.Logger
	Services
	Deps
}

func New(
	l zerolog.Logger,
	services Services,
	deps Deps,
) *HTTPHandler {
	return &HTTPHandler{
		l:        l,
		Services: services,
		Deps:     deps,
	}
}

func (h *HTTPHandler) Handler() *chi.Mux {
	r := chi.NewRouter()

	h.useMiddleware(r)

	r.Route("/", func(r chi.Router) {
		r.Get("/home", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Welcome to the Home Page!"))
		})
	})

	r.Route(h.BasePath, func(r chi.Router) {
		h.userRoute(r)
		h.authRoute(r)
		h.roleRoute(r.With(h.verifyAccToken))
	})

	return r
}
