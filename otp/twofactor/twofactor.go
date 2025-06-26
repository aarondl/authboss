package twofactor

import "github.com/aarondl/authboss/v3"

// Page constants
const (
	PageRecovery2FA  = "recovery2fa"
	PageVerify2FA    = "twofactor_verify"
	PageVerifyEnd2FA = "twofactor_verify_end"
)

// Email constants
const (
	EmailVerifyHTML = "twofactor_verify_email_html"
	EmailVerifyTxt  = "twofactor_verify_email_txt"
)

// Form value constants
const (
	FormValueToken = "token"
)

// Data constants
const (
	DataRecoveryCode     = "recovery_code"
	DataRecoveryCodes    = "recovery_codes"
	DataNumRecoveryCodes = "n_recovery_codes"
	DataVerifyEmail      = "email"
	DataVerifyURL        = "url"
)

const (
	alphabet             = "abcdefghijkmnopqrstuvwxyz0123456789"
	recoveryCodeLength   = 10
	verifyEmailTokenSize = 16
)

// User interface
type User interface {
	authboss.User

	GetEmail() string
	PutEmail(string)

	// GetRecoveryCodes retrieves a CSV string of bcrypt'd recovery codes
	GetRecoveryCodes() string
	// PutRecoveryCodes uses a single string to store many
	// bcrypt'd recovery codes
	PutRecoveryCodes(codes string)
}
