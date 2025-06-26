package sms2fa

import (
	"fmt"

	"github.com/aarondl/authboss/v3"
)

// SMSValuer returns a code or a resend-code from the body
type SMSValuer interface {
	authboss.Validator

	GetCode() string
	GetRecoveryCode() string
}

// SMSPhoneNumberValuer returns a phone number from the body
type SMSPhoneNumberValuer interface {
	authboss.Validator

	GetPhoneNumber() string
}

// MustHaveSMSValues upgrades a validatable set of values
// to one specifically holding the code we're looking for, or a resend.
func MustHaveSMSValues(v authboss.Validator) SMSValuer {
	if u, ok := v.(SMSValuer); ok {
		return u
	}

	panic(fmt.Sprintf("bodyreader returned a type that could not be upgraded to SMSValuer: %T", v))
}

// MustHaveSMSPhoneNumberValue upgrades a validatable set of values
// to ones specifically holding a phone number.
func MustHaveSMSPhoneNumberValue(v authboss.Validator) SMSPhoneNumberValuer {
	if u, ok := v.(SMSPhoneNumberValuer); ok {
		return u
	}

	panic(fmt.Sprintf("bodyreader returned a type that could not be upgraded to SMSValuer: %T", v))
}
