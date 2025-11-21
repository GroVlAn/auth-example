package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/GroVlAn/auth-example/internal/core"
	"github.com/GroVlAn/auth-example/internal/core/e"
	"github.com/jmoiron/sqlx"
)

type UserRepo interface {
	Create(ctx context.Context, user core.User) error
	GetByEmail(ctx context.Context, email string) (core.User, error)
	GetByUsername(ctx context.Context, username string) (core.User, error)
	GetByID(ctx context.Context, id string) (core.User, error)
	ExistByEmail(ctx context.Context, email string) (bool, error)
	ExistByUsername(ctx context.Context, username string) (bool, error)
}

type AuthRepo interface {
	CreateTokens(ctx context.Context, accToken core.AccessToken, rfToken core.RefreshToken, artID string) error
	CreateAccessToken(ctx context.Context, token core.AccessToken) error
	AccessToken(ctx context.Context, token string) (core.AccessToken, error)
	DeleteAccessToken(ctx context.Context, token string) error
	DeleteAllAccessTokens(ctx context.Context, userID string) error
	RefreshToken(ctx context.Context, token string) (core.RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, token string) error
	DeleteAllRefreshTokens(ctx context.Context, userID string) error
}

type Repository struct {
	userRepo UserRepo
	authRepo AuthRepo
}

func New(db *sqlx.DB) *Repository {
	return &Repository{
		userRepo: NewUserRepository(db),
		authRepo: NewAuthRepository(db),
	}
}

func (r *Repository) User() UserRepo {
	return r.userRepo
}

func (r *Repository) Auth() AuthRepo {
	return r.authRepo
}

func handleQueryError(err error, msg string) error {
	if errors.Is(err, sql.ErrNoRows) {
		return e.NewErrNotFound(
			err,
			msg,
		)
	}

	return e.NewErrInternal(
		err,
	)
}

func withTx(ctx context.Context, db *sqlx.DB, fn func(*sqlx.Tx) error) error {
	tx, err := db.BeginTxx(ctx, nil)
	if err != nil {
		return e.NewErrInternal(fmt.Errorf("begin tx: %w", err))
	}
	defer tx.Rollback()

	if err := fn(tx); err != nil {
		return err
	}

	return tx.Commit()
}
