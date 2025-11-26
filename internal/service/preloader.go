package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/GroVlAn/auth-example/internal/config"
	"github.com/GroVlAn/auth-example/internal/core"
	"github.com/google/uuid"
)

type roleRepo interface {
	CreateRole(ctx context.Context, role core.Role) error
	RoleExist(ctx context.Context, roleName string) (bool, error)
	Role(ctx context.Context, roleName string) (core.Role, error)
	CreatePermission(ctx context.Context, permission core.Permission, roleID, rpID string) error
	Permissions(ctx context.Context, roleName string) ([]core.Permission, error)
}

type superuserRepo interface {
	Create(ctx context.Context, user core.User) error
	SetRole(ctx context.Context, userID string, roleID string) error
	SuperuserExist(ctx context.Context) (bool, error)
}

type PreloaderDeps struct {
	DefRolePath string
	HashCost    int
}

type Preloader struct {
	roleRepo roleRepo
	userRepo superuserRepo
	PreloaderDeps
}

func NewRoleLoader(roleRepo roleRepo, userRepo superuserRepo, deps PreloaderDeps) *Preloader {
	return &Preloader{
		roleRepo:      roleRepo,
		userRepo:      userRepo,
		PreloaderDeps: deps,
	}
}

func (p *Preloader) CreateDefaultRoles(ctx context.Context) error {
	rolesList, err := load(p.DefRolePath)
	if err != nil {
		return fmt.Errorf("loading default roles from config: %w", err)
	}

	for _, element := range rolesList {
		ok, err := p.roleRepo.RoleExist(ctx, element.Name)
		if err != nil {
			return fmt.Errorf("checking existed role: %w", err)
		}
		if ok {
			continue
		}
		role := core.Role{
			ID:          uuid.NewString(),
			Name:        element.Name,
			Description: element.Description,
			IsDefault:   true,
			CreatedAt:   time.Now(),
		}

		err = p.roleRepo.CreateRole(ctx, role)
		if err != nil {
			return fmt.Errorf("creating new default role: %w", err)
		}

		p.createPermissions(ctx, element.Permissions, role.ID)
	}

	return nil
}

func (p *Preloader) CreateSuperuser(ctx context.Context, superuser config.Superuser) error {
	ok, err := p.userRepo.SuperuserExist(ctx)
	if err != nil {
		return fmt.Errorf("checking existed superuser: %w", err)
	}
	if ok {
		return nil
	}

	user := core.User{
		ID:          uuid.NewString(),
		Username:    superuser.Login,
		Email:       superuser.Email,
		Password:    superuser.Password,
		Fullname:    "admin admin",
		IsSuperuser: true,
		IsActive:    true,
		CreatedAt:   time.Now(),
	}

	if err := validateUser(user); err != nil {
		return err
	}

	passwordHash, err := passwordHash(user.Password, p.HashCost)
	if err != nil {
		return err
	}

	user.PasswordHash = passwordHash

	err = p.userRepo.Create(ctx, user)
	if err != nil {
		return fmt.Errorf("creating user: %w", err)
	}

	superuserRole, err := p.roleRepo.Role(ctx, superuser.Role)
	if err != nil {
		return fmt.Errorf("getting exist superuser role: %w", err)
	}

	if err := p.userRepo.SetRole(ctx, user.ID, superuserRole.ID); err != nil {
		return fmt.Errorf("setting superuser role: %w", err)
	}

	return nil
}

func (p *Preloader) createPermissions(ctx context.Context, permissionsList []core.PermissionElement, roleID string) error {
	for _, prem := range permissionsList {
		permission := core.Permission{
			ID:          uuid.NewString(),
			Name:        prem.Name,
			Description: prem.Description,
			IsDefault:   true,
			CreatedAt:   time.Now(),
		}

		if err := p.roleRepo.CreatePermission(ctx, permission, roleID, uuid.NewString()); err != nil {
			return fmt.Errorf("creating new default permission: %w", err)
		}
	}

	return nil
}

func load(path string) ([]core.RoleElement, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var roles []core.RoleElement
	if err = json.Unmarshal(file, &roles); err != nil {
		return nil, fmt.Errorf("unmarshaling roles config: %w", err)
	}

	return roles, nil
}
