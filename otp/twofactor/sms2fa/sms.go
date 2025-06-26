// Package sms2fa implements two factor auth using
// sms-transmitted one time passwords.
package sms2fa

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/friendsofgo/errors"
	"github.com/aarondl/authboss/v3"
	"github.com/aarondl/authboss/v3/otp/twofactor"
)

// Session keys
const (
	SessionSMSNumber     = "sms_number"
	SessionSMSSecret     = "sms_secret"
	SessionSMSLast       = "sms_last"
	SessionSMSPendingPID = "sms_pending"
)

// Form value constants
const (
	FormValueCode        = "code"
	FormValuePhoneNumber = "phone_number"
)

// Pages
const (
	successSuffix = "_success"

	PageSMSConfirm        = "sms2fa_confirm"
	PageSMSConfirmSuccess = "sms2fa_confirm_success"
	PageSMSRemove         = "sms2fa_remove"
	PageSMSRemoveSuccess  = "sms2fa_remove_success"
	PageSMSSetup          = "sms2fa_setup"
	PageSMSValidate       = "sms2fa_validate"
)

// Data constants
const (
	DataSMSSecret      = SessionSMSSecret
	DataSMSPhoneNumber = "sms_phone_number"
)

const (
	smsCodeLength       = 6
	smsRateLimitSeconds = 10
)

var (
	errSMSRateLimit   = errors.New("user sms send rate-limited")
	errBadPhoneNumber = errors.New("bad phone number provided")
)

// User for SMS
type User interface {
	twofactor.User

	GetSMSPhoneNumber() string
	PutSMSPhoneNumber(string)
}

// SMSNumberProvider provides a phone number already attached
// to the user if it exists. This allows a user to be populated
// with a phone-number without the user needing to provide it.
type SMSNumberProvider interface {
	GetSMSPhoneNumberSeed() string
}

// SMSSender sends SMS messages to a phone number
type SMSSender interface {
	Send(ctx context.Context, number, text string) error
}

// SMS implements time based one time passwords
type SMS struct {
	*authboss.Authboss
	Sender SMSSender
}

// SMSValidator abstracts the send code/resend code/submit code workflow
type SMSValidator struct {
	*SMS
	Page string
}

// Setup the module
func (s *SMS) Setup() error {
	if s.Sender == nil {
		return errors.New("must have SMS.Sender set")
	}

	var unauthedResponse authboss.MWRespondOnFailure
	if s.Config.Modules.ResponseOnUnauthed != 0 {
		unauthedResponse = s.Config.Modules.ResponseOnUnauthed
	} else if s.Config.Modules.RoutesRedirectOnUnauthed {
		unauthedResponse = authboss.RespondRedirect
	}
	abmw := authboss.MountedMiddleware2(s.Authboss, true, authboss.RequireFullAuth, unauthedResponse)

	var middleware, verified func(func(w http.ResponseWriter, r *http.Request) error) http.Handler
	middleware = func(handler func(http.ResponseWriter, *http.Request) error) http.Handler {
		return abmw(s.Core.ErrorHandler.Wrap(handler))
	}

	if s.Authboss.Config.Modules.TwoFactorEmailAuthRequired {
		setupPath := path.Join(s.Authboss.Paths.Mount, "/2fa/sms/setup")
		emailVerify, err := twofactor.SetupEmailVerify(s.Authboss, "sms", setupPath)
		if err != nil {
			return err
		}
		verified = func(handler func(http.ResponseWriter, *http.Request) error) http.Handler {
			return abmw(emailVerify.Wrap(s.Core.ErrorHandler.Wrap(handler)))
		}
	} else {
		verified = middleware
	}

	s.Authboss.Core.Router.Get("/2fa/sms/setup", verified(s.GetSetup))
	s.Authboss.Core.Router.Post("/2fa/sms/setup", verified(s.PostSetup))

	confirm := &SMSValidator{SMS: s, Page: PageSMSConfirm}
	s.Authboss.Core.Router.Get("/2fa/sms/confirm", verified(confirm.Get))
	s.Authboss.Core.Router.Post("/2fa/sms/confirm", verified(confirm.Post))

	remove := &SMSValidator{SMS: s, Page: PageSMSRemove}
	s.Authboss.Core.Router.Get("/2fa/sms/remove", middleware(remove.Get))
	s.Authboss.Core.Router.Post("/2fa/sms/remove", middleware(remove.Post))

	validate := &SMSValidator{SMS: s, Page: PageSMSValidate}
	s.Authboss.Core.Router.Get("/2fa/sms/validate", s.Core.ErrorHandler.Wrap(validate.Get))
	s.Authboss.Core.Router.Post("/2fa/sms/validate", s.Core.ErrorHandler.Wrap(validate.Post))

	s.Authboss.Events.Before(authboss.EventAuthHijack, s.HijackAuth)

	return s.Authboss.Core.ViewRenderer.Load(
		PageSMSConfirm,
		PageSMSConfirmSuccess,
		PageSMSRemove,
		PageSMSRemoveSuccess,
		PageSMSSetup,
		PageSMSValidate,
	)
}

// HijackAuth stores the user's pid in a special temporary session variable
// and redirects them to the validation endpoint.
func (s *SMS) HijackAuth(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
	if handled {
		return false, nil
	}

	user := r.Context().Value(authboss.CTXKeyUser).(User)

	number := user.GetSMSPhoneNumber()
	if len(number) == 0 {
		return false, nil
	}

	authboss.PutSession(w, SessionSMSPendingPID, user.GetPID())
	err := s.SendCodeToUser(w, r, user.GetPID(), number)
	if err != nil && err != errSMSRateLimit {
		return false, err
	}

	var query string
	if len(r.URL.RawQuery) != 0 {
		query = "?" + r.URL.RawQuery
	}
	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: s.Paths.Mount + "/2fa/sms/validate" + query,
	}
	return true, s.Authboss.Config.Core.Redirector.Redirect(w, r, ro)
}

// SendCodeToUser ensures that a code is sent to the user
func (s *SMS) SendCodeToUser(w http.ResponseWriter, r *http.Request, pid, number string) error {
	code, err := generateRandomCode()
	if err != nil {
		return err
	}

	logger := s.RequestLogger(r)

	if len(number) == 0 {
		return errBadPhoneNumber
	}

	lastStr, ok := authboss.GetSession(r, SessionSMSLast)
	suppress := false
	if ok {
		last, err := strconv.ParseInt(lastStr, 10, 64)
		if err != nil {
			return err
		}
		suppress = time.Now().UTC().Unix()-last < smsRateLimitSeconds
	}

	if suppress {
		logger.Infof("rate-limited sms for %s to %s", pid, number)
		return errSMSRateLimit
	}

	authboss.PutSession(w, SessionSMSLast, strconv.FormatInt(time.Now().UTC().Unix(), 10))
	authboss.PutSession(w, SessionSMSSecret, code)

	logger.Infof("sending sms for %s to %s", pid, number)
	if err := s.Sender.Send(r.Context(), number, code); err != nil {
		logger.Infof("failed to send sms for %s to %s: %+v", pid, number, err)
		return err
	}

	return nil
}

// GetSetup shows a screen that allows a user to opt in to setting up sms 2fa
// by asking for a phone number that's optionally already filled in.
func (s *SMS) GetSetup(w http.ResponseWriter, r *http.Request) error {
	abUser, err := s.CurrentUser(r)
	if err != nil {
		return err
	}

	var data authboss.HTMLData
	numberProvider, ok := abUser.(SMSNumberProvider)
	if ok {
		if val := numberProvider.GetSMSPhoneNumberSeed(); len(val) != 0 {
			data = authboss.HTMLData{DataSMSPhoneNumber: val}
		}
	}

	authboss.DelSession(w, SessionSMSSecret)
	authboss.DelSession(w, SessionSMSNumber)

	return s.Core.Responder.Respond(w, r, http.StatusOK, PageSMSSetup, data)
}

// PostSetup adds the phone number provided to the user's session and sends
// an SMS there.
func (s *SMS) PostSetup(w http.ResponseWriter, r *http.Request) error {
	abUser, err := s.CurrentUser(r)
	if err != nil {
		return err
	}
	user := abUser.(User)

	validator, err := s.Authboss.Config.Core.BodyReader.Read(PageSMSSetup, r)
	if err != nil {
		return err
	}

	smsVals := MustHaveSMSPhoneNumberValue(validator)

	number := smsVals.GetPhoneNumber()
	if len(number) == 0 {
		data := authboss.HTMLData{
			authboss.DataValidation: map[string][]string{FormValuePhoneNumber: {
				s.Localizef(r.Context(), authboss.TxtSMSNumberRequired),
			}},
		}
		return s.Core.Responder.Respond(w, r, http.StatusOK, PageSMSSetup, data)
	}

	authboss.PutSession(w, SessionSMSNumber, number)
	if err = s.SendCodeToUser(w, r, user.GetPID(), number); err != nil {
		return err
	}

	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: s.Paths.Mount + "/2fa/sms/confirm",
	}
	return s.Core.Redirector.Redirect(w, r, ro)
}

// Get shows an empty page typically, this allows us to prompt
// a second time for the action.
func (s *SMSValidator) Get(w http.ResponseWriter, r *http.Request) error {
	return s.Core.Responder.Respond(w, r, http.StatusOK, s.Page, nil)
}

// Post receives a code in the body and validates it, if the code is
// missing then it sends the code to the user (rate-limited).
func (s *SMSValidator) Post(w http.ResponseWriter, r *http.Request) error {
	// Get the user, they're either logged in and CurrentUser works, or they're
	// in the middle of logging in and SMSPendingPID is set.
	// Ensure we always look up CurrentUser first or session persistence
	// attacks can be performed.
	abUser, err := s.Authboss.CurrentUser(r)
	if err == authboss.ErrUserNotFound {
		pid, ok := authboss.GetSession(r, SessionSMSPendingPID)
		if ok && len(pid) != 0 {
			abUser, err = s.Authboss.Config.Storage.Server.Load(r.Context(), pid)
		}
	}
	if err != nil {
		return err
	}

	user := abUser.(User)

	validator, err := s.Authboss.Config.Core.BodyReader.Read(s.Page, r)
	if err != nil {
		return err
	}
	smsCodeValues := MustHaveSMSValues(validator)

	var inputCode, recoveryCode string
	inputCode = smsCodeValues.GetCode()

	// Only allow recovery codes on login/remove operations
	if s.Page == PageSMSValidate || s.Page == PageSMSRemove {
		recoveryCode = smsCodeValues.GetRecoveryCode()
	}

	if len(recoveryCode) == 0 && len(inputCode) == 0 {
		return s.sendCode(w, r, user)
	}

	if len(recoveryCode) != 0 {
		return s.validateCode(w, r, user, "", recoveryCode)
	}

	return s.validateCode(w, r, user, inputCode, "")
}

func (s *SMSValidator) sendCode(w http.ResponseWriter, r *http.Request, user User) error {
	var phoneNumber string

	// Get the phone number, when we're confirming the phone number is not
	// yet stored in the user but inside the session.
	switch s.Page {
	case PageSMSConfirm:
		var ok bool
		phoneNumber, ok = authboss.GetSession(r, SessionSMSNumber)
		if !ok {
			return errors.New("request failed, no sms number present in session")
		}

	case PageSMSValidate, PageSMSRemove:
		phoneNumber = user.GetSMSPhoneNumber()
	}

	if len(phoneNumber) == 0 {
		return errors.Errorf("no phone number was available in PostSendCode for user %s", user.GetPID())
	}

	var data authboss.HTMLData
	err := s.SendCodeToUser(w, r, user.GetPID(), phoneNumber)
	if err == errSMSRateLimit {
		data = authboss.HTMLData{authboss.DataErr: s.Localizef(r.Context(), authboss.TxtSMSWaitToResend)}
	} else if err != nil {
		return err
	}

	return s.Core.Responder.Respond(w, r, http.StatusOK, s.Page, data)
}

func (s *SMSValidator) validateCode(w http.ResponseWriter, r *http.Request, user User, inputCode, recoveryCode string) error {
	logger := s.RequestLogger(r)

	var verified bool
	if len(recoveryCode) != 0 {
		var ok bool
		recoveryCodes := twofactor.DecodeRecoveryCodes(user.GetRecoveryCodes())
		recoveryCodes, ok = twofactor.UseRecoveryCode(recoveryCodes, recoveryCode)

		verified = ok

		if verified {
			logger.Infof("user %s used recovery code instead of sms2fa", user.GetPID())
			user.PutRecoveryCodes(twofactor.EncodeRecoveryCodes(recoveryCodes))
			if err := s.Authboss.Config.Storage.Server.Save(r.Context(), user); err != nil {
				return err
			}
		}
	} else {
		code, ok := authboss.GetSession(r, SessionSMSSecret)
		if !ok || len(code) == 0 {
			return errors.Errorf("no code in session for user %s", user.GetPID())
		}

		verified = 1 == subtle.ConstantTimeCompare([]byte(inputCode), []byte(code))
	}

	if !verified {
		r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
		handled, err := s.Authboss.Events.FireAfter(authboss.EventAuthFail, w, r)
		if err != nil {
			return err
		} else if handled {
			return nil
		}

		logger.Infof("user %s sms 2fa failure (wrong code)", user.GetPID())
		data := authboss.HTMLData{
			authboss.DataValidation: map[string][]string{FormValueCode: {s.Localizef(r.Context(), authboss.TxtInvalid2FACode)}},
		}
		return s.Authboss.Core.Responder.Respond(w, r, http.StatusOK, s.Page, data)
	}

	var data authboss.HTMLData

	switch s.Page {
	case PageSMSConfirm:
		phoneNumber, ok := authboss.GetSession(r, SessionSMSNumber)
		if !ok {
			return errors.New("request failed, no sms number present in session")
		}

		codes, err := twofactor.GenerateRecoveryCodes()
		if err != nil {
			return err
		}

		crypted, err := twofactor.BCryptRecoveryCodes(codes)
		if err != nil {
			return err
		}

		// Save the user which activates 2fa (phone number should be stored from earlier)
		user.PutSMSPhoneNumber(phoneNumber)
		user.PutRecoveryCodes(twofactor.EncodeRecoveryCodes(crypted))
		if err = s.Authboss.Config.Storage.Server.Save(r.Context(), user); err != nil {
			return err
		}

		authboss.DelSession(w, authboss.Session2FAAuthed)
		authboss.DelSession(w, SessionSMSSecret)
		authboss.DelSession(w, SessionSMSNumber)

		logger.Infof("user %s enabled sms 2fa", user.GetPID())
		data = authboss.HTMLData{twofactor.DataRecoveryCodes: codes}

		r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
		if handled, err := s.Authboss.Events.FireAfter(authboss.EventTwoFactorAdded, w, r); err != nil {
			return err
		} else if handled {
			return nil
		}

	case PageSMSRemove:
		user.PutSMSPhoneNumber("")
		if err := s.Authboss.Config.Storage.Server.Save(r.Context(), user); err != nil {
			return err
		}

		authboss.DelSession(w, authboss.Session2FA)

		r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
		if handled, err := s.Authboss.Events.FireAfter(authboss.EventTwoFactorRemoved, w, r); err != nil {
			return err
		} else if handled {
			return nil
		}

		logger.Infof("user %s disabled sms 2fa", user.GetPID())
	case PageSMSValidate:
		authboss.PutSession(w, authboss.SessionKey, user.GetPID())
		authboss.PutSession(w, authboss.Session2FA, "sms")

		authboss.DelSession(w, authboss.SessionHalfAuthKey)
		authboss.DelSession(w, SessionSMSPendingPID)
		authboss.DelSession(w, SessionSMSSecret)

		logger.Infof("user %s sms 2fa success", user.GetPID())

		r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
		handled, err := s.Authboss.Events.FireAfter(authboss.EventAuth, w, r)
		if err != nil {
			return err
		} else if handled {
			return nil
		}

		ro := authboss.RedirectOptions{
			Code:             http.StatusTemporaryRedirect,
			RedirectPath:     s.Authboss.Config.Paths.AuthLoginOK,
			FollowRedirParam: true,
		}
		return s.Authboss.Core.Redirector.Redirect(w, r, ro)
	default:
		return errors.New("unknown action for sms validate")
	}

	return s.Authboss.Core.Responder.Respond(w, r, http.StatusOK, s.Page+successSuffix, data)
}

// generateRandomCode for sms auth
func generateRandomCode() (code string, err error) {
	sb := new(strings.Builder)

	random := make([]byte, smsCodeLength)
	if _, err = io.ReadFull(rand.Reader, random); err != nil {
		return "", err
	}

	for i := range random {
		sb.WriteByte(random[i]%10 + 48)
	}

	return sb.String(), nil
}
