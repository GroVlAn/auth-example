package service

import (
	"fmt"
	"net/mail"
	"strings"
	"unicode"

	"github.com/GroVlAn/auth-example/internal/core"
	"github.com/GroVlAn/auth-example/internal/core/e"
	"golang.org/x/crypto/bcrypt"
)

func passwordHash(password string, hashCost int) (string, error) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), hashCost)
	if err != nil {
		return "", e.NewErrInternal(
			fmt.Errorf("hashing password: %w", err),
		)
	}

	return string(passwordHash), nil
}

func validateUser(user core.User) *e.ErrValidation {
	err := e.NewErrValidation("validation user data error")

	if len(user.Username) == 0 {
		err.AddField("username", "username is required")
	} else if len(user.Username) < minUsernameLen {
		err.AddField("username", "username is short")
	}

	if ok, reason := validateEmail(user.Email); !ok {
		err.AddField("email", reason)
	}

	if ok, reason := validatePassword(user.Password); !ok {
		err.AddField("password", reason)
	}

	if ok, reason := validateFullname(user.Fullname); !ok {
		err.AddField("fullname", reason)
	}

	if err.IsEmpty() {
		return nil
	}

	return err
}

func validatePassword(password string) (bool, string) {
	if len(password) < minPasswordLen {
		return false, "password is required"
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

	if !(isNumber && isLower && isUpper && isSymbol) {
		return false, invalidPasswordMsg
	}

	return true, ""
}

func validateEmail(email string) (bool, string) {
	if len(email) == 0 {
		return false, "email is required"
	}

	_, err := mail.ParseAddress(email)
	if err != nil {
		return false, "invalid email"
	}

	return true, ""
}

func validateFullname(fullname string) (bool, string) {
	if len(fullname) == 0 {
		return false, "fullname is required"
	}

	parts := strings.Fields(fullname)

	if len(parts) < 2 {
		return false, "fullname must has first name and second name"
	}

	for _, ch := range fullname {
		if unicode.IsDigit(ch) || unicode.IsSymbol(ch) || unicode.IsPunct(ch) {
			return false, "fullname must has only letters"
		}
	}

	return true, ""
}
