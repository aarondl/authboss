// Package twofactor allows authentication via one time passwords
package twofactor

import (
	"crypto/rand"
	"io"
	"net/http"
	"strings"

	"github.com/aarondl/authboss/v3"
	"golang.org/x/crypto/bcrypt"
)

// Recovery for two-factor authentication is handled by this type
type Recovery struct {
	*authboss.Authboss
}

// Setup the module to provide recovery regeneration routes
func (rc *Recovery) Setup() error {
	var unauthedResponse authboss.MWRespondOnFailure
	if rc.Config.Modules.ResponseOnUnauthed != 0 {
		unauthedResponse = rc.Config.Modules.ResponseOnUnauthed
	} else if rc.Config.Modules.RoutesRedirectOnUnauthed {
		unauthedResponse = authboss.RespondRedirect
	}
	middleware := authboss.MountedMiddleware2(rc.Authboss, true, authboss.RequireFullAuth, unauthedResponse)
	rc.Authboss.Core.Router.Get("/2fa/recovery/regen", middleware(rc.Authboss.Core.ErrorHandler.Wrap(rc.GetRegen)))
	rc.Authboss.Core.Router.Post("/2fa/recovery/regen", middleware(rc.Authboss.Core.ErrorHandler.Wrap(rc.PostRegen)))

	return rc.Authboss.Core.ViewRenderer.Load(PageRecovery2FA)
}

// GetRegen shows a button that enables a user to regen their codes
// as well as how many codes are currently remaining.
func (rc *Recovery) GetRegen(w http.ResponseWriter, r *http.Request) error {
	abUser, err := rc.CurrentUser(r)
	if err != nil {
		return err
	}
	user := abUser.(User)

	var nCodes int
	codes := user.GetRecoveryCodes()
	if len(codes) != 0 {
		nCodes++
	}
	for _, c := range codes {
		if c == ',' {
			nCodes++
		}
	}

	data := authboss.HTMLData{DataNumRecoveryCodes: nCodes}
	return rc.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageRecovery2FA, data)
}

// PostRegen regenerates the codes
func (rc *Recovery) PostRegen(w http.ResponseWriter, r *http.Request) error {
	abUser, err := rc.CurrentUser(r)
	if err != nil {
		return err
	}
	user := abUser.(User)

	codes, err := GenerateRecoveryCodes()
	if err != nil {
		return err
	}

	hashedCodes, err := BCryptRecoveryCodes(codes)
	if err != nil {
		return err
	}

	user.PutRecoveryCodes(EncodeRecoveryCodes(hashedCodes))
	if err = rc.Authboss.Config.Storage.Server.Save(r.Context(), user); err != nil {
		return err
	}

	data := authboss.HTMLData{DataRecoveryCodes: codes}
	return rc.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageRecovery2FA, data)
}

// GenerateRecoveryCodes creates 10 recovery codes of the form:
// abd34-1b24do (using alphabet, of length recoveryCodeLength).
func GenerateRecoveryCodes() ([]string, error) {
	byt := make([]byte, 10*recoveryCodeLength)
	if _, err := io.ReadFull(rand.Reader, byt); err != nil {
		return nil, err
	}

	codes := make([]string, 10)
	for i := range codes {
		builder := new(strings.Builder)
		for j := 0; j < recoveryCodeLength; j++ {
			if recoveryCodeLength/2 == j {
				builder.WriteByte('-')
			}

			randNumber := byt[i*recoveryCodeLength+j] % byte(len(alphabet))
			builder.WriteByte(alphabet[randNumber])
		}
		codes[i] = builder.String()
	}

	return codes, nil
}

// BCryptRecoveryCodes hashes each recovery code given and return them in a new
// slice.
func BCryptRecoveryCodes(codes []string) ([]string, error) {
	cryptedCodes := make([]string, len(codes))
	for i, c := range codes {
		hash, err := bcrypt.GenerateFromPassword([]byte(c), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}

		cryptedCodes[i] = string(hash)
	}

	return cryptedCodes, nil
}

// UseRecoveryCode deletes the code that was used from the string slice and
// returns it, the bool is true if a code was used
func UseRecoveryCode(codes []string, inputCode string) ([]string, bool) {
	input := []byte(inputCode)
	use := -1

	for i, c := range codes {
		err := bcrypt.CompareHashAndPassword([]byte(c), input)
		if err == nil {
			use = i
			break
		}
	}

	if use < 0 {
		return nil, false
	}

	ret := make([]string, len(codes)-1)
	for j := range codes {
		if j == use {
			continue
		}
		set := j
		if j > use {
			set--
		}
		ret[set] = codes[j]
	}

	return ret, true
}

// EncodeRecoveryCodes is an alias for strings.Join(",")
func EncodeRecoveryCodes(codes []string) string { return strings.Join(codes, ",") }

// DecodeRecoveryCodes is an alias for strings.Split(",")
func DecodeRecoveryCodes(codes string) []string { return strings.Split(codes, ",") }
