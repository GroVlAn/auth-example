package service

import (
	"context"
	"fmt"
	"net/mail"
	"strings"
	"time"
	"unicode"

	"github.com/GroVlAn/auth-example/internal/core"
	"github.com/GroVlAn/auth-example/internal/core/e"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
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
	if err := us.validateUser(user); err != nil {
		return err
	}

	user.ID = uuid.NewString()
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(user.Password), us.HashCost)
	if err != nil {
		return e.NewErrInternal(
			fmt.Errorf("hashing password: %w", err),
		)
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

func (us *userService) validateUser(user core.User) *e.ErrValidation {
	err := e.NewErrValidation("validation user data error")

	if len(user.Username) == 0 {
		err.AddField("username", "username is required")
	} else if len(user.Username) < minUsernameLen {
		err.AddField("username", "username is short")
	}

	if len(user.Email) == 0 {
		err.AddField("email", "email is required")
	} else if !us.validateEmail(user.Email) {
		err.AddField("email", "invalid email")
	}

	if len(user.Password) == 0 {
		err.AddField("password", "password is required")
	} else if !us.validatePassword(user.Password) {
		err.AddField("password", invalidPasswordMsg)
	}

	if len(user.Fullname) == 0 {
		err.AddField("fullname", "fullname is required")
	} else if !us.validateFullname(user.Fullname) {
		err.AddField("fullname", "invalid fullname")
	}

	if err.IsEmpty() {
		return nil
	}

	return err
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
func (us *userService) validatePassword(password string) bool {
	if len(password) < minPasswordLen {
		return false
	}

	var (
		isNumber bool
		isLower  bool
		isUpper  bool
		isSymbol bool
	)

	for _, ch := range password {
		switch {
		case unicode.IsNumber(ch) && !isNumber:
			isNumber = true
		case unicode.IsLower(ch) && !isLower:
			isLower = true
		case unicode.IsUpper(ch) && !isUpper:
			isUpper = true
		case (unicode.IsPunct(ch) || unicode.IsSymbol(ch)) && !isSymbol:
			isSymbol = true
		}
	}

	return isNumber && isLower && isUpper && isSymbol
}

func (us *userService) validateEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func (us *userService) validateFullname(fullname string) bool {
	if len(fullname) == 0 {
		return false
	}

	parts := strings.Fields(fullname)

	if len(parts) < 2 {
		return false
	}

	for _, ch := range fullname {
		if unicode.IsDigit(ch) || unicode.IsSymbol(ch) || unicode.IsPunct(ch) {
			return false
		}
	}

	return true
}
