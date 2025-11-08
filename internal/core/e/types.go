package e

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
