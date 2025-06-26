package totp2fa

import (
	"fmt"

	"github.com/aarondl/authboss/v3"
)

// TOTPCodeValuer returns a code from the body
type TOTPCodeValuer interface {
	authboss.Validator

	GetCode() string
	GetRecoveryCode() string
}

// MustHaveTOTPCodeValues upgrades a validatable set of values
// to ones specific to a user that needs to be recovered.
func MustHaveTOTPCodeValues(v authboss.Validator) TOTPCodeValuer {
	if u, ok := v.(TOTPCodeValuer); ok {
		return u
	}

	panic(fmt.Sprintf("bodyreader returned a type that could not be upgraded to TOTPCodeValuer: %T", v))
}
