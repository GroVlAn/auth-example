package e

import (
	"errors"
	"fmt"
)

type ErrorType int

var (
	ErrUserAlreadyExists = errors.New("user already exists")
)

const (
	ErrorTypeNotFound ErrorType = iota
	ErrorTypeConflict
	ErrorTypeValidation
	ErrorTypeUnauthorized
	ErrorTypeInternal
)

type ValidationJSON struct {
	ErrorType string            `json:"error_type"`
	Message   string            `json:"message"`
	Fields    map[string]string `json:"fields,omitempty"`
}

type ErrWrapper struct {
	errType ErrorType
	err     error
	msg     string
}

type ErrValidation struct {
	ErrWrapper
	fields map[string]string
}

func NewErrValidation(msg string) *ErrValidation {
	return &ErrValidation{
		ErrWrapper: ErrWrapper{
			errType: ErrorTypeValidation,
			msg:     msg,
		},
		fields: make(map[string]string),
	}
}

func (ev *ErrValidation) AddField(field, reason string) {
	ev.fields[field] = reason
}

func (ev *ErrValidation) Error() string {
	return ev.msg
}

func (ev *ErrValidation) Data() ValidationJSON {
	return ValidationJSON{
		ErrorType: "validation_error",
		Message:   ev.msg,
		Fields:    ev.fields,
	}
}

func (ev *ErrValidation) IsEmpty() bool {
	return len(ev.fields) == 0
}

func NewErrNotFound(err error, msg string) *ErrWrapper {
	return &ErrWrapper{
		errType: ErrorTypeNotFound,
		err:     err,
		msg:     msg,
	}
}

func NewErrConflict(err error, msg string) *ErrWrapper {
	return &ErrWrapper{
		errType: ErrorTypeConflict,
		err:     err,
		msg:     msg,
	}
}

func NewErrUnauthorized(err error, msg string) *ErrWrapper {
	return &ErrWrapper{
		errType: ErrorTypeUnauthorized,
		err:     err,
		msg:     msg,
	}
}

func NewErrInternal(err error) *ErrWrapper {
	return &ErrWrapper{
		errType: ErrorTypeInternal,
		err:     err,
		msg:     "internal server error",
	}
}

func (ew *ErrWrapper) Error() string {
	return ew.msg
}

func (ew *ErrWrapper) Unwrap() error {
	return ew.err
}

func (ew *ErrWrapper) ErrorType() ErrorType {
	return ew.errType
}

type ErrEmptyFields struct {
	Fields []string
}

func (e ErrEmptyFields) Error() string {
	return "the following fields are empty: " + fmt.Sprint(e.Fields)
}
