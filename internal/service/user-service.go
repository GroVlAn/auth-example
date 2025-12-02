package service

import (
	"context"
	"fmt"
	"time"

	"github.com/GroVlAn/auth-example/internal/core"
	"github.com/GroVlAn/auth-example/internal/core/e"
	"github.com/google/uuid"
)

const (
	minUsernameLen = 4
	minPasswordLen = 8

	invalidPasswordMsg = "Password must be at least 8 characters long and contain: one uppercase letter, one lowercase letter, one number, and one special symbol"
)

type userRoleRepo interface {
	Role(ctx context.Context, roleName string) (core.Role, error)
}

type userRepo interface {
	Create(ctx context.Context, user core.User) error
	GetByEmail(ctx context.Context, email string) (core.User, error)
	GetByUsername(ctx context.Context, username string) (core.User, error)
	GetByID(ctx context.Context, id string) (core.User, error)
	ExistByEmail(ctx context.Context, email string) (bool, error)
	ExistByUsername(ctx context.Context, username string) (bool, error)
	SetRole(ctx context.Context, userID string, roleID string) error
	BanUser(ctx context.Context, userID string) error
	UnbanUser(ctx context.Context, userID string) error
	InactivateUser(ctx context.Context, userID string) error
	RestoreUser(ctx context.Context, userID string) error
	DeleteInactiveUser(ctx context.Context) error
}

type DepsUserService struct {
	HashCost int
}

type userService struct {
	userRepo userRepo
	roleRepo userRoleRepo
	DepsUserService
}

func NewUserService(userRepo userRepo, roleRepo userRoleRepo, deps DepsUserService) *userService {
	return &userService{
		userRepo:        userRepo,
		roleRepo:        roleRepo,
		DepsUserService: deps,
	}
}

func (us *userService) CreateUser(ctx context.Context, user core.User) error {
	if err := validateUser(user); err != nil {
		return err
	}

	user.ID = uuid.NewString()
	passwordHash, err := passwordHash(user.Password, us.HashCost)
	if err != nil {
		return err
	}

	user.PasswordHash = string(passwordHash)

	exist, err := us.userRepo.ExistByEmail(ctx, user.Email)
	if err != nil {
		return err
	}
	if exist {
		return e.NewErrConflict(
			e.ErrUserAlreadyExists,
			e.ErrUserAlreadyExists.Error(),
		)
	}

	exist, err = us.userRepo.ExistByUsername(ctx, user.Username)
	if err != nil {
		return err
	}
	if exist {
		return e.NewErrConflict(
			e.ErrUserAlreadyExists,
			e.ErrUserAlreadyExists.Error(),
		)
	}

	user.CreatedAt = time.Now()

	return us.userRepo.Create(ctx, user)
}

func (us *userService) User(ctx context.Context, userReq core.UserRequest) (core.User, error) {
	if err := us.validateUserRequest(userReq); err != nil {
		return core.User{}, err
	}

	switch {
	case userReq.ID != "":
		return us.userRepo.GetByID(ctx, userReq.ID)
	case userReq.Username != "":
		return us.userRepo.GetByUsername(ctx, userReq.Username)
	default:
		return us.userRepo.GetByEmail(ctx, userReq.Email)
	}
}

func (us *userService) SetRole(ctx context.Context, userID string, roleName string) error {
	role, err := us.roleRepo.Role(ctx, roleName)
	if err != nil {
		return fmt.Errorf("getting role by name: %w", err)
	}

	if err := us.userRepo.SetRole(ctx, userID, role.ID); err != nil {
		return fmt.Errorf("setting role to user: %w", err)
	}

	return nil
}

func (us *userService) InactivateUser(ctx context.Context, userReq core.UserRequest) error {
	user, err := us.User(ctx, userReq)
	if err != nil {
		return fmt.Errorf("getting user: %w", err)
	}

	if err := us.userRepo.InactivateUser(ctx, user.ID); err != nil {
		return fmt.Errorf("inactivating user: %w", err)
	}

	return nil
}

func (us *userService) RestoreUser(ctx context.Context, userReq core.UserRequest) error {
	user, err := us.User(ctx, userReq)
	if err != nil {
		return fmt.Errorf("getting user: %w", err)
	}

	if err := us.userRepo.RestoreUser(ctx, user.ID); err != nil {
		return fmt.Errorf("restoring user: %w", err)
	}

	return nil
}

func (us *userService) BanUser(ctx context.Context, userReq core.UserRequest) error {
	user, err := us.User(ctx, userReq)
	if err != nil {
		return fmt.Errorf("getting user: %w", err)
	}

	if err := us.userRepo.BanUser(ctx, user.ID); err != nil {
		return fmt.Errorf("banning user: %w", err)
	}

	return nil
}

func (us *userService) UnbanUser(ctx context.Context, userReq core.UserRequest) error {
	user, err := us.User(ctx, userReq)
	if err != nil {
		return fmt.Errorf("getting user: %w", err)
	}

	if err := us.userRepo.UnbanUser(ctx, user.ID); err != nil {
		return fmt.Errorf("unbanning user: %w", err)
	}

	return nil
}

func (us *userService) DeleteInactiveUser(ctx context.Context) error {
	if err := us.userRepo.DeleteInactiveUser(ctx); err != nil {
		return fmt.Errorf("deleting inactive users: %w", err)
	}

	return nil
}

func (us *userService) validateUserRequest(userReq core.UserRequest) *e.ErrValidation {
	err := e.NewErrValidation("validation user request data error")

	if userReq.ID == "" && userReq.Username == "" && userReq.Email == "" {
		err.AddField("id|username|email", "at least one field must be provided")
	}

	if err.IsEmpty() {
		return nil
	}

	return err

}
