package service

import (
	"context"
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

type userRepo interface {
	Create(ctx context.Context, user core.User) error
	GetByEmail(ctx context.Context, email string) (core.User, error)
	GetByUsername(ctx context.Context, username string) (core.User, error)
	GetByID(ctx context.Context, id string) (core.User, error)
	ExistByEmail(ctx context.Context, email string) (bool, error)
	ExistByUsername(ctx context.Context, username string) (bool, error)
}

type DepsUserService struct {
	HashCost int
}

type userService struct {
	repo userRepo
	DepsUserService
}

func NewUserService(repo userRepo, deps DepsUserService) *userService {
	return &userService{
		repo:            repo,
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

	exist, err := us.repo.ExistByEmail(ctx, user.Email)
	if err != nil {
		return err
	}
	if exist {
		return e.NewErrConflict(
			e.ErrUserAlreadyExists,
			e.ErrUserAlreadyExists.Error(),
		)
	}

	exist, err = us.repo.ExistByUsername(ctx, user.Username)
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

	return us.repo.Create(ctx, user)
}

func (us *userService) User(ctx context.Context, userReq core.UserRequest) (core.User, error) {
	if err := us.validateUserRequest(userReq); err != nil {
		return core.User{}, err
	}

	switch {
	case userReq.ID != "":
		return us.repo.GetByID(ctx, userReq.ID)
	case userReq.Username != "":
		return us.repo.GetByUsername(ctx, userReq.Username)
	default:
		return us.repo.GetByEmail(ctx, userReq.Email)
	}
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
