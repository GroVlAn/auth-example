package repository

import (
	"context"

	"github.com/GroVlAn/auth-example/internal/core"
	"github.com/jmoiron/sqlx"
)

type UserRepo interface {
	Create(ctx context.Context, user core.User) error
	GetByEmail(ctx context.Context, email string) (core.User, error)
	GetByUsername(ctx context.Context, username string) (core.User, error)
	GetByID(ctx context.Context, id string) (core.User, error)
	SetRole(ctx context.Context, userID string, roleID string) error
	SuperuserExist(ctx context.Context) (bool, error)
	ExistByEmail(ctx context.Context, email string) (bool, error)
	ExistByUsername(ctx context.Context, username string) (bool, error)
	BanUser(ctx context.Context, userID string) error
	UnbanUser(ctx context.Context, userID string) error
	InactivateUser(ctx context.Context, userID string) error
	RestoreUser(ctx context.Context, userID string) error
	DeleteInactiveUser(ctx context.Context) error
}

type AuthRepo interface {
	CreateTokens(ctx context.Context, accToken core.AccessToken, rfToken core.RefreshToken, artID string) error
	CreateAccessToken(ctx context.Context, token core.AccessToken) error
	AccessToken(ctx context.Context, token string) (core.AccessToken, error)
	DeleteAccessToken(ctx context.Context, token string) error
	DeleteAllAccessTokens(ctx context.Context, userID string) error
	RefreshToken(ctx context.Context, token string) (core.RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, token string) error
	DeleteAllRefreshTokens(ctx context.Context, token string) error
}

type RoleRepo interface {
	CreateRole(ctx context.Context, role core.Role) error
	RoleExist(ctx context.Context, roleName string) (bool, error)
	Role(ctx context.Context, roleName string) (core.Role, error)
	CreatePermission(ctx context.Context, permission core.Permission, roleID, rpID string) error
	Permissions(ctx context.Context, roleName string) ([]core.Permission, error)
}

type Repository struct {
	userRepo UserRepo
	authRepo AuthRepo
	roleRepo RoleRepo
}

func New(db *sqlx.DB) *Repository {
	return &Repository{
		userRepo: NewUserRepository(db),
		authRepo: NewAuthRepository(db),
		roleRepo: NewRoleRepository(db),
	}
}

func (r *Repository) User() UserRepo {
	return r.userRepo
}

func (r *Repository) Auth() AuthRepo {
	return r.authRepo
}

func (r *Repository) Role() RoleRepo {
	return r.roleRepo
}
