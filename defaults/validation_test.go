package defaults

import (
	"testing"

	"github.com/aarondl/authboss/v3"
)

func TestValidate(t *testing.T) {
	t.Parallel()

	validator := HTTPFormValidator{
		Values: map[string]string{
			"username": "john",
			"email":    "john@john.com",
		},
		Ruleset: []Rules{
			{
				FieldName: "username",
				MinLength: 5,
			},
			{
				FieldName: "missing_field",
				Required:  true,
			},
		},
	}

	errList := authboss.ErrorList(validator.Validate())

	errs := errList.Map()
	if errs["username"][0] != "Must be at least 5 characters" {
		t.Error("Expected a different error for username:", errs["username"][0])
	}
	if errs["missing_field"][0] != "Cannot be blank" {
		t.Error("Expected a different error for missing_field:", errs["missing_field"][0])
	}
	if _, ok := errs["email"]; ok {
		t.Error("Expected no errors for email.")
	}
}

func TestValidate_Confirm(t *testing.T) {
	t.Parallel()

	validator := HTTPFormValidator{
		Values: map[string]string{
			"username":         "john",
			"confirm_username": "johnny",
		},
		ConfirmFields: []string{"username", "confirm_username"},
	}

	mapped := authboss.ErrorList(validator.Validate()).Map()
	if mapped["confirm_username"][0] != "Does not match username" {
		t.Error("Expected a different error for confirmUsername:", mapped["confirmUsername"][0])
	}

	validator.Values = map[string]string{
		"username":         "john",
		"confirm_username": "john",
	}
	errs := authboss.ErrorList(validator.Validate())
	if len(errs) != 0 {
		t.Error("Expected no errors:", errs)
	}

	validator = HTTPFormValidator{
		ConfirmFields: []string{"username"},
	}

	paniced := false
	defer func() {
		if r := recover(); r != nil {
			paniced = true
		}
	}()

	errs = validator.Validate()
	if len(errs) != 0 {
		t.Error("Expected no errors:", errs)
	}

	if !paniced {
		t.Error("Want a panic due to bad confirm fields slice")
	}
}
