// Package otp allows authentication through a one time password
// instead of a traditional password.
package otp

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/friendsofgo/errors"
	"github.com/aarondl/authboss/v3"
)

const (
	otpSize = 16
	maxOTPs = 5

	// PageLogin is for identifying the login page for parsing & validation
	PageLogin = "otplogin"
	// PageAdd is for adding an otp to the user
	PageAdd = "otpadd"
	// PageClear is for deleting all the otps from the user
	PageClear = "otpclear"

	// DataNumberOTPs shows the number of otps for add/clear operations
	DataNumberOTPs = "otp_count"
	// DataOTP shows the new otp that was added
	DataOTP = "otp"
)

// User for one time passwords
type User interface {
	authboss.User

	// GetOTPs retrieves a string of comma separated bcrypt'd one time passwords
	GetOTPs() string
	// PutOTPs puts a string of comma separated bcrypt'd one time passwords
	PutOTPs(string)
}

// MustBeOTPable ensures the user can use one time passwords
func MustBeOTPable(user authboss.User) User {
	u, ok := user.(User)
	if !ok {
		panic(fmt.Sprintf("could not upgrade user to an otpable user, type: %T", u))
	}

	return u
}

func init() {
	authboss.RegisterModule("otp", &OTP{})
}

// OTP module
type OTP struct {
	*authboss.Authboss
}

// Init module
func (o *OTP) Init(ab *authboss.Authboss) (err error) {
	o.Authboss = ab

	if err = o.Authboss.Config.Core.ViewRenderer.Load(PageLogin, PageAdd, PageClear); err != nil {
		return err
	}

	o.Authboss.Config.Core.Router.Get("/otp/login", o.Authboss.Core.ErrorHandler.Wrap(o.LoginGet))
	o.Authboss.Config.Core.Router.Post("/otp/login", o.Authboss.Core.ErrorHandler.Wrap(o.LoginPost))

	var unauthedResponse authboss.MWRespondOnFailure
	if ab.Config.Modules.ResponseOnUnauthed != 0 {
		unauthedResponse = ab.Config.Modules.ResponseOnUnauthed
	} else if ab.Config.Modules.RoutesRedirectOnUnauthed {
		unauthedResponse = authboss.RespondRedirect
	}
	middleware := authboss.MountedMiddleware2(ab, true, authboss.RequireNone, unauthedResponse)
	o.Authboss.Config.Core.Router.Get("/otp/add", middleware(o.Authboss.Core.ErrorHandler.Wrap(o.AddGet)))
	o.Authboss.Config.Core.Router.Post("/otp/add", middleware(o.Authboss.Core.ErrorHandler.Wrap(o.AddPost)))

	o.Authboss.Config.Core.Router.Get("/otp/clear", middleware(o.Authboss.Core.ErrorHandler.Wrap(o.ClearGet)))
	o.Authboss.Config.Core.Router.Post("/otp/clear", middleware(o.Authboss.Core.ErrorHandler.Wrap(o.ClearPost)))

	return nil
}

// LoginGet simply displays the login form
func (o *OTP) LoginGet(w http.ResponseWriter, r *http.Request) error {
	var data authboss.HTMLData
	if redir := r.URL.Query().Get(authboss.FormValueRedirect); len(redir) != 0 {
		data = authboss.HTMLData{authboss.FormValueRedirect: redir}
	}
	return o.Core.Responder.Respond(w, r, http.StatusOK, PageLogin, data)
}

// LoginPost attempts to validate the credentials passed in
// to log in a user.
func (o *OTP) LoginPost(w http.ResponseWriter, r *http.Request) error {
	logger := o.RequestLogger(r)

	validatable, err := o.Authboss.Core.BodyReader.Read(PageLogin, r)
	if err != nil {
		return err
	}

	// Skip validation since all the validation happens during the database lookup and
	// password check.
	creds := authboss.MustHaveUserValues(validatable)

	pid := creds.GetPID()
	pidUser, err := o.Authboss.Storage.Server.Load(r.Context(), pid)
	if err == authboss.ErrUserNotFound {
		logger.Infof("failed to load user requested by pid: %s", pid)
		data := authboss.HTMLData{authboss.DataErr: o.Localizef(r.Context(), authboss.TxtInvalidCredentials)}
		return o.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageLogin, data)
	} else if err != nil {
		return err
	}

	otpUser := MustBeOTPable(pidUser)
	passwords := splitOTPs(otpUser.GetOTPs())

	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, pidUser))

	inputSum := sha512.Sum512([]byte(creds.GetPassword()))
	matchPassword := -1
	for i, p := range passwords {
		dbSum, err := base64.StdEncoding.DecodeString(p)
		if err != nil {
			return errors.Wrap(err, "otp in database was not valid base64")
		}

		if 1 == subtle.ConstantTimeCompare(inputSum[:], dbSum) {
			matchPassword = i
			break
		}
	}

	var handled bool
	if matchPassword < 0 {
		handled, err = o.Authboss.Events.FireAfter(authboss.EventAuthFail, w, r)
		if err != nil {
			return err
		} else if handled {
			return nil
		}

		logger.Infof("user %s failed to log in with otp", pid)
		data := authboss.HTMLData{authboss.DataErr: o.Localizef(r.Context(), authboss.TxtInvalidCredentials)}
		return o.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageLogin, data)
	}

	logger.Infof("removing otp password from %s", pid)
	passwords[matchPassword] = passwords[len(passwords)-1]
	passwords = passwords[:len(passwords)-1]
	otpUser.PutOTPs(joinOTPs(passwords))
	if err = o.Authboss.Config.Storage.Server.Save(r.Context(), pidUser); err != nil {
		return err
	}

	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyValues, validatable))

	handled, err = o.Events.FireBefore(authboss.EventAuth, w, r)
	if err != nil {
		return err
	} else if handled {
		return nil
	}

	handled, err = o.Events.FireBefore(authboss.EventAuthHijack, w, r)
	if err != nil {
		return err
	} else if handled {
		return nil
	}

	logger.Infof("user %s logged in via otp", pid)
	authboss.PutSession(w, authboss.SessionKey, pid)
	authboss.DelSession(w, authboss.SessionHalfAuthKey)

	handled, err = o.Authboss.Events.FireAfter(authboss.EventAuth, w, r)
	if err != nil {
		return err
	} else if handled {
		return nil
	}

	ro := authboss.RedirectOptions{
		Code:             http.StatusTemporaryRedirect,
		RedirectPath:     o.Authboss.Paths.AuthLoginOK,
		FollowRedirParam: true,
	}
	return o.Authboss.Core.Redirector.Redirect(w, r, ro)
}

// AddGet shows how many passwords exist and allows the user to create a new one
func (o *OTP) AddGet(w http.ResponseWriter, r *http.Request) error {
	return o.showOTPCount(w, r, PageAdd)
}

// AddPost adds a new password to the user and displays it
func (o *OTP) AddPost(w http.ResponseWriter, r *http.Request) error {
	logger := o.RequestLogger(r)

	user, err := o.Authboss.CurrentUser(r)
	if err != nil {
		return err
	}

	otpUser := MustBeOTPable(user)
	currentOTPs := splitOTPs(otpUser.GetOTPs())

	if len(currentOTPs) >= maxOTPs {
		data := authboss.HTMLData{authboss.DataValidation: o.Localizef(r.Context(), authboss.TxtTooManyOTPs, maxOTPs)}
		return o.Core.Responder.Respond(w, r, http.StatusOK, PageAdd, data)
	}

	logger.Infof("generating otp for %s", user.GetPID())
	otp, hash, err := generateOTP()
	if err != nil {
		return err
	}

	currentOTPs = append(currentOTPs, hash)
	otpUser.PutOTPs(joinOTPs(currentOTPs))

	if err := o.Authboss.Config.Storage.Server.Save(r.Context(), user); err != nil {
		return err
	}

	return o.Core.Responder.Respond(w, r, http.StatusOK, PageAdd, authboss.HTMLData{DataOTP: otp})
}

// ClearGet shows how many passwords exist and allows the user to clear them all
func (o *OTP) ClearGet(w http.ResponseWriter, r *http.Request) error {
	return o.showOTPCount(w, r, PageClear)
}

// ClearPost clears all otps that are stored for the user.
func (o *OTP) ClearPost(w http.ResponseWriter, r *http.Request) error {
	logger := o.RequestLogger(r)

	user, err := o.Authboss.CurrentUser(r)
	if err != nil {
		return err
	}

	logger.Infof("clearing all otps for user: %s", user.GetPID())
	otpUser := MustBeOTPable(user)
	otpUser.PutOTPs("")

	if err := o.Authboss.Config.Storage.Server.Save(r.Context(), user); err != nil {
		return err
	}

	return o.Core.Responder.Respond(w, r, http.StatusOK, PageAdd, authboss.HTMLData{DataNumberOTPs: "0"})
}

func (o *OTP) showOTPCount(w http.ResponseWriter, r *http.Request, page string) error {
	user, err := o.Authboss.CurrentUser(r)
	if err != nil {
		return err
	}

	otpUser := MustBeOTPable(user)
	ln := strconv.Itoa(len(splitOTPs(otpUser.GetOTPs())))

	return o.Core.Responder.Respond(w, r, http.StatusOK, page, authboss.HTMLData{DataNumberOTPs: ln})
}

func joinOTPs(otps []string) string {
	return strings.Join(otps, ",")
}

func splitOTPs(otps string) []string {
	if len(otps) == 0 {
		return nil
	}

	return strings.Split(otps, ",")
}

func generateOTP() (otp string, hash string, err error) {
	secret := make([]byte, otpSize)
	if _, err = io.ReadFull(rand.Reader, secret); err != nil {
		return "", "", err
	}

	otp = fmt.Sprintf("%x-%x-%x-%x",
		secret[0:4],
		secret[4:8],
		secret[8:12],
		secret[12:16],
	)

	sum := sha512.Sum512([]byte(otp))
	encoded := make([]byte, base64.StdEncoding.EncodedLen(sha512.Size))
	base64.StdEncoding.Encode(encoded, sum[:])
	hash = string(encoded)

	return otp, hash, nil
}
