package defaults

import (
	"fmt"

	"github.com/aarondl/authboss/v3"
)

// HTTPFormValidator validates HTTP post type inputs
type HTTPFormValidator struct {
	Values map[string]string

	Ruleset       []Rules
	ConfirmFields []string
}

// Validate validates a request using the given ruleset.
func (h HTTPFormValidator) Validate() []error {
	var errList authboss.ErrorList

	for _, rule := range h.Ruleset {
		field := rule.FieldName

		val := h.Values[field]
		if errs := rule.Errors(val); len(errs) > 0 {
			errList = append(errList, errs...)
		}
	}

	if l := len(h.ConfirmFields); l != 0 && l%2 != 0 {
		panic("HTTPFormValidator given an odd number of confirm fields")
	}

	for i := 0; i < len(h.ConfirmFields)-1; i += 2 {
		main := h.Values[h.ConfirmFields[i]]
		if len(main) == 0 {
			continue
		}

		confirm := h.Values[h.ConfirmFields[i+1]]
		if len(confirm) == 0 || main != confirm {
			errList = append(errList, FieldError{h.ConfirmFields[i+1], fmt.Errorf("Does not match %s", h.ConfirmFields[i])})
		}
	}

	return errList
}

// FieldError represents an error that occurs during validation and is always
// attached to field on a form.
type FieldError struct {
	FieldName string
	FieldErr  error
}

// NewFieldError literally only exists because of poor name planning
// where name and err can't be exported on the struct due to the method names
func NewFieldError(name string, err error) FieldError {
	return FieldError{FieldName: name, FieldErr: err}
}

// Name of the field the error is about
func (f FieldError) Name() string {
	return f.FieldName
}

// Err for the field
func (f FieldError) Err() error {
	return f.FieldErr
}

// Error in string form
func (f FieldError) Error() string {
	return fmt.Sprintf("%s: %v", f.FieldName, f.FieldErr)
}
