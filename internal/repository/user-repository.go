package repository

import (
	"context"
	"fmt"

	"github.com/GroVlAn/auth-example/internal/core"
	"github.com/GroVlAn/auth-example/internal/core/e"
	"github.com/jmoiron/sqlx"
)

const (
	userTable = "tododler_user"
)

type userRepository struct {
	db *sqlx.DB
}

func NewUserRepository(db *sqlx.DB) *userRepository {
	return &userRepository{
		db: db,
	}
}

func (ur *userRepository) Create(ctx context.Context, user core.User) error {
	query := fmt.Sprintf(
		"INSERT INTO %s (id, username, email, password_hash, full_name, created_at) VALUES (:id, :username, :email, :password_hash, :full_name, :created_at)",
		userTable,
	)

	_, err := ur.db.NamedExecContext(ctx, query, user)
	if err != nil {
		return e.NewErrInternal(
			fmt.Errorf("creating new user: %w", err),
		)
	}

	return nil
}

func (ur *userRepository) GetByEmail(ctx context.Context, email string) (core.User, error) {
	query := fmt.Sprintf("SELECT id, username, email, password_hash, full_name, created_at FROM %s WHERE email = $1", userTable)

	var user core.User
	err := ur.db.GetContext(ctx, &user, query, email)
	if err != nil {
		return core.User{}, handleQueryError(fmt.Errorf(
			"getting user by email: %w", err),
			"user not found",
		)
	}

	return user, nil
}

func (ur *userRepository) GetByUsername(ctx context.Context, username string) (core.User, error) {
	query := fmt.Sprintf("SELECT id, username, email, password_hash, full_name, created_at FROM %s WHERE username = $1", userTable)

	var user core.User
	err := ur.db.GetContext(ctx, &user, query, username)
	if err != nil {
		return core.User{}, handleQueryError(fmt.Errorf(
			"getting user by username: %w", err),
			"user not found",
		)
	}

	return user, nil
}

func (ur *userRepository) GetByID(ctx context.Context, id string) (core.User, error) {
	query := fmt.Sprintf("SELECT id, username, email, password_hash, full_name, created_at FROM %s WHERE id = $1", userTable)

	var user core.User
	err := ur.db.GetContext(ctx, &user, query, id)
	if err != nil {
		return core.User{}, handleQueryError(fmt.Errorf(
			"getting user by id: %w", err),
			"user not found",
		)
	}

	return user, nil
}

func (ur *userRepository) ExistByEmail(ctx context.Context, email string) (bool, error) {
	query := fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM %s WHERE email = $1)", userTable)

	var exists bool
	err := ur.db.GetContext(ctx, &exists, query, email)
	if err != nil {
		return false, e.NewErrInternal(
			fmt.Errorf("checking if user exists by email: %w", err),
		)
	}

	return exists, nil
}

func (ur *userRepository) ExistByUsername(ctx context.Context, username string) (bool, error) {
	query := fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM %s WHERE username = $1)", userTable)

	var exists bool
	err := ur.db.GetContext(ctx, &exists, query, username)
	if err != nil {
		return false, e.NewErrInternal(
			fmt.Errorf("checking if user exists by username: %w", err),
		)
	}

	return exists, nil
}
