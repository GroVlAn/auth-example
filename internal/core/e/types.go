package e

type ErrorType int

const (
	ErrorTypeNotFound ErrorType = iota
	ErrorTypeConflict
	ErrorTypeValidation
	ErrorTypeUnauthorized
	ErrorTypeInternal
)

type ValidationJSON struct {
	ErrorType string      `json:"error_type"`
	Message   string      `json:"message"`
	Fields    [][2]string `json:"fields,omitempty"`
}
