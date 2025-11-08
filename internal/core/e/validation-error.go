package e

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
