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
	roleTable           = "role"
	permissionTable     = "permission"
	rolePermissionTable = "role_permission"
)

type RoleRepository struct {
	db *sqlx.DB
}

func NewRoleRepository(db *sqlx.DB) *RoleRepository {
	return &RoleRepository{
		db: db,
	}
}

func (rr *RoleRepository) CreateRole(ctx context.Context, role core.Role) error {
	query := fmt.Sprintf(
		`INSERT INTO %s (id, name, description, is_default, created_at) VALUES(:id, :name, :description, :is_default, :created_at)`,
		roleTable,
	)

	_, err := rr.db.NamedExecContext(ctx, query, role)
	if err != nil {
		return e.NewErrInternal(err)
	}

	return nil
}

func (rr *RoleRepository) RoleExist(ctx context.Context, roleName string) (bool, error) {
	query := fmt.Sprintf(
		`SELECT EXISTS(SELECT 1 FROM %s WHERE name=$1)`,
		roleTable,
	)

	var exist bool
	err := rr.db.GetContext(ctx, &exist, query, roleName)
	if err != nil {
		return false, e.NewErrInternal(err)
	}

	return exist, nil
}

func (rr *RoleRepository) Role(ctx context.Context, roleName string) (core.Role, error) {
	query := fmt.Sprintf(
		`SELECT id, name, description, is_default, created_at FROM %s WHERE name=$1`,
		roleTable,
	)

	var role core.Role
	if err := rr.db.GetContext(ctx, &role, query, roleName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return core.Role{}, e.NewErrNotFound(err, "role not found")
		}

		return core.Role{}, e.NewErrInternal(err)
	}

	return role, nil
}

func (rr *RoleRepository) RoleByID(ctx context.Context, roleID string) (core.Role, error) {
	query := fmt.Sprintf(
		`SELECT id, name, description, is_default, created_at FROM %s WHERE id=$1`,
		roleTable,
	)

	var role core.Role
	if err := rr.db.GetContext(ctx, &role, query, roleID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return core.Role{}, e.NewErrNotFound(err, "role not found")
		}

		return core.Role{}, e.NewErrInternal(err)
	}

	return role, nil
}

func (rr *RoleRepository) CreatePermission(ctx context.Context, permission core.Permission, roleID, rpID string) error {
	return withTx(ctx, rr.db, func(tx *sqlx.Tx) error {
		queryFindPermission := fmt.Sprintf(
			`SELECT EXISTS(SELECT 1 FROM %s WHERE name=$1)`,
			permissionTable,
		)

		var exist bool
		err := tx.GetContext(ctx, &exist, queryFindPermission, permission.Name)
		if err != nil {
			return e.NewErrInternal(
				fmt.Errorf("getting permission: %w", err),
			)
		}
		if !exist {
			if err := rr.createPermission(ctx, tx, permission); err != nil {
				return err
			}
		}

		queryCreateRolePermission := fmt.Sprintf(
			`INSERT INTO %s (id, role_id, permission_id) VALUES ($1, $2, $3)`,
			rolePermissionTable,
		)
		_, err = tx.ExecContext(ctx, queryCreateRolePermission, rpID, roleID, permission.ID)
		if err != nil {
			return e.NewErrInternal(err)
		}

		return nil
	})
}

func (rr *RoleRepository) Permissions(ctx context.Context, roleID string) ([]core.Permission, error) {
	query := fmt.Sprintf(
		`SELECT p.id, p.name, p.description, p.is_default, p.created_at FROM %s p
		JOIN %s rp ON p.id == rp.permission_id WHERE rp.role_id = $1`,
		permissionTable,
		roleTable,
	)

	var permissions []core.Permission

	err := rr.db.SelectContext(ctx, &permissions, query, roleID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, e.NewErrNotFound(
			fmt.Errorf("getting permissions: %w", err),
			"permissions not found",
		)
	} else if err != nil {
		return nil, handleQueryError(
			fmt.Errorf("selecting permissions: %w", err),
			"permissions not found",
		)
	}

	return permissions, nil
}

func (rr *RoleRepository) createPermission(ctx context.Context, tx *sqlx.Tx, permission core.Permission) error {
	queryCreatePermission := fmt.Sprintf(
		`INSERT INTO %s (id, name, description, is_default, created_at) VALUES(:id, :name, :description, :is_default, :created_at)`,
		permissionTable)

	_, err := tx.NamedExecContext(ctx, queryCreatePermission, permission)
	if err != nil {
		return e.NewErrInternal(
			fmt.Errorf("creating permission: %w", err),
		)
	}

	return nil
}
