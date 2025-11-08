package e

import (
	"errors"
)

type ErrorType int

var (
	ErrUserAlreadyExists = errors.New("user already exists")
)
