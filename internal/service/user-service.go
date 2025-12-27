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

type userCache interface {
	SetUser(user core.User)
	GetUserByID(id string) (core.User, bool)
	GetUserByUsername(username string) (core.User, bool)
	GetUserByEmail(email string) (core.User, bool)
	DeleteUser(user core.User)
	ClearUsers()
}

type UserDeps struct {
	HashCost int
}

type userService struct {
	userRepo userRepo
	roleRepo userRoleRepo
	cache    userCache
	UserDeps
}

func NewUserService(
	userRepo userRepo,
	roleRepo userRoleRepo,
	cache userCache,
	deps UserDeps,
) *userService {
	return &userService{
		userRepo: userRepo,
		roleRepo: roleRepo,
		cache:    cache,
		UserDeps: deps,
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

	if err = us.userRepo.Create(ctx, user); err != nil {
		return fmt.Errorf("creating user: %w", err)
	}

	us.cache.SetUser(user)

	return nil
}

func (us *userService) User(ctx context.Context, userReq core.UserRequest) (core.User, error) {
	if err := us.validateUserRequest(userReq); err != nil {
		return core.User{}, err
	}

	switch {
	case userReq.ID != "":
		return us.getUserByID(ctx, userReq.ID)
	case userReq.Username != "":
		return us.getUserByUsername(ctx, userReq.Username)
	default:
		return us.getUserByEmail(ctx, userReq.Email)
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

	user, err := us.User(ctx, core.UserRequest{
		ID: userID,
	})
	if err != nil {
		return fmt.Errorf("getting user: %w", err)
	}

	us.cache.DeleteUser(user)
	us.cache.SetUser(user)

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

	us.cache.DeleteUser(user)

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

	us.cache.SetUser(user)

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

	us.cache.DeleteUser(user)

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

	us.cache.SetUser(user)

	return nil
}

func (us *userService) DeleteInactiveUser(ctx context.Context) error {
	if err := us.userRepo.DeleteInactiveUser(ctx); err != nil {
		return fmt.Errorf("deleting inactive users: %w", err)
	}

	us.cache.ClearUsers()

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

func (us *userService) getUserByID(ctx context.Context, id string) (core.User, error) {
	if user, ok := us.cache.GetUserByID(id); ok {
		return user, nil
	}

	user, err := us.userRepo.GetByID(ctx, id)
	if err != nil {
		return core.User{}, fmt.Errorf("getting user by id: %w", err)
	}

	return user, nil
}

func (us *userService) getUserByUsername(ctx context.Context, username string) (core.User, error) {
	if user, ok := us.cache.GetUserByUsername(username); ok {
		return user, nil
	}

	user, err := us.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return core.User{}, fmt.Errorf("getting user by username: %w", err)
	}

	return user, nil
}

func (us *userService) getUserByEmail(ctx context.Context, email string) (core.User, error) {
	if user, ok := us.cache.GetUserByEmail(email); ok {
		return user, nil
	}

	user, err := us.userRepo.GetByEmail(ctx, email)
	if err != nil {
		return core.User{}, fmt.Errorf("getting user by email: %w", err)
	}

	return user, nil
}
