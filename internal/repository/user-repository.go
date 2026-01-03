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

const (
	userTable = "auth_user"
)

type UserRepository struct {
	db *sqlx.DB
}

func NewUserRepository(db *sqlx.DB) *UserRepository {
	return &UserRepository{
		db: db,
	}
}

func (ur *UserRepository) Create(ctx context.Context, user core.User) error {
	query := fmt.Sprintf(
		`INSERT INTO %s (id, username, email, password_hash, fullname, is_superuser, 
		created_at) VALUES (:id, :username, :email, :password_hash, :fullname, :is_superuser,
		:created_at)`,
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

func (ur *UserRepository) SetRole(ctx context.Context, userID string, roleID string) error {
	query := fmt.Sprintf(
		`UPDATE %s SET role_id=$1 WHERE id=$2`,
		userTable,
	)

	_, err := ur.db.ExecContext(ctx, query, roleID, userID)
	if err != nil {
		return e.NewErrInternal(err)
	}

	return nil
}

func (ur *UserRepository) IsSuperuser(ctx context.Context, userID string) (bool, error) {
	query := fmt.Sprintf(
		`SELECT id FROM %s WHERE id=$1 AND is_superuser=true`,
		userTable,
	)

	_, err := ur.db.ExecContext(ctx, query, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, e.NewErrInternal(err)
	}

	return true, nil
}

func (ur *UserRepository) SuperuserExist(ctx context.Context) (bool, error) {
	query := fmt.Sprintf(
		`SELECT EXISTS(SELECT 1 FROM %s WHERE is_superuser=true)`,
		userTable,
	)

	var exist bool
	if err := ur.db.GetContext(ctx, &exist, query); err != nil {
		return false, e.NewErrInternal(err)
	}

	return exist, nil
}

func (ur *UserRepository) GetByEmail(ctx context.Context, email string) (core.User, error) {
	query := fmt.Sprintf(
		`SELECT id, username, email, password_hash, fullname, created_at FROM %s
		WHERE email = $1`,
		userTable,
	)

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

func (ur *UserRepository) GetByUsername(ctx context.Context, username string) (core.User, error) {
	query := fmt.Sprintf(
		`SELECT id, username, email, password_hash, fullname, created_at FROM %s
		WHERE username = $1`,
		userTable,
	)

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

func (ur *UserRepository) GetByID(ctx context.Context, id string) (core.User, error) {
	query := fmt.Sprintf(
		`SELECT id, username, email, password_hash, fullname, created_at FROM %s 
		WHERE id = $1`,
		userTable,
	)

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

func (ur *UserRepository) ExistByEmail(ctx context.Context, email string) (bool, error) {
	query := fmt.Sprintf(
		`SELECT EXISTS(SELECT 1 FROM %s WHERE email = $1)`,
		userTable,
	)

	var exists bool
	err := ur.db.GetContext(ctx, &exists, query, email)
	if err != nil {
		return false, e.NewErrInternal(
			fmt.Errorf("checking if user exists by email: %w", err),
		)
	}

	return exists, nil
}

func (ur *UserRepository) ExistByUsername(ctx context.Context, username string) (bool, error) {
	query := fmt.Sprintf(
		`SELECT EXISTS(SELECT 1 FROM %s WHERE username = $1)`,
		userTable,
	)

	var exists bool
	err := ur.db.GetContext(ctx, &exists, query, username)
	if err != nil {
		return false, e.NewErrInternal(
			fmt.Errorf("checking if user exists by username: %w", err),
		)
	}

	return exists, nil
}

func (ur *UserRepository) BanUser(ctx context.Context, userID string) error {
	query := fmt.Sprintf(
		`UPDATE %s SET is_banned=true WHERE id=$1`,
		userTable,
	)

	if _, err := ur.db.ExecContext(ctx, query, userID); err != nil {
		return e.NewErrInternal(err)
	}

	return nil
}

func (ur *UserRepository) UnbanUser(ctx context.Context, userID string) error {
	query := fmt.Sprintf(
		`UPDATE %s SET is_banned=false WHERE id=$1`,
		userTable,
	)

	if _, err := ur.db.ExecContext(ctx, query, userID); err != nil {
		return e.NewErrInternal(err)
	}

	return nil
}

func (ur *UserRepository) InactivateUser(ctx context.Context, userID string) error {
	query := fmt.Sprintf(
		`UPDATE %s SET is_active=false WHERE id=$1`,
		userTable,
	)

	if _, err := ur.db.ExecContext(ctx, query, userID); err != nil {
		return e.NewErrInternal(err)
	}

	return nil
}

func (ur *UserRepository) RestoreUser(ctx context.Context, userID string) error {
	query := fmt.Sprintf(
		`UPDATE %s SET is_active=true WHERE id=$1`,
		userTable,
	)

	if _, err := ur.db.ExecContext(ctx, query, userID); err != nil {
		return e.NewErrInternal(err)
	}

	return nil
}

func (ur *UserRepository) DeleteInactiveUser(ctx context.Context) error {
	query := fmt.Sprintf(
		`DELETE FROM %s WHERE is_active=false`,
		userTable,
	)

	if _, err := ur.db.ExecContext(ctx, query); err != nil {
		return e.NewErrInternal(err)
	}

	return nil
}
