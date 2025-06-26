// Package totp2fa implements two factor auth using time-based
// one time passwords.
package totp2fa

import (
	"bytes"
	"context"
	"fmt"
	"image/png"
	"io"
	"net/http"
	"net/url"
	"path"

	"github.com/friendsofgo/errors"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/aarondl/authboss/v3"
	"github.com/aarondl/authboss/v3/otp/twofactor"
)

const (
	otpKeyFormat = "otpauth://totp/%s:%s?issuer=%s&secret=%s"
)

// Session keys
const (
	SessionTOTPSecret     = "totp_secret"
	SessionTOTPPendingPID = "totp_pending"
)

// Pages
const (
	PageTOTPConfirm        = "totp2fa_confirm"
	PageTOTPConfirmSuccess = "totp2fa_confirm_success"
	PageTOTPRemove         = "totp2fa_remove"
	PageTOTPRemoveSuccess  = "totp2fa_remove_success"
	PageTOTPSetup          = "totp2fa_setup"
	PageTOTPValidate       = "totp2fa_validate"
)

// Form value constants
const (
	FormValueCode = "code"
)

// Data constants
const (
	DataTOTPSecret = SessionTOTPSecret
)

var errNoTOTPEnabled = errors.New("user does not have totp 2fa enabled")

// User for TOTP
type User interface {
	twofactor.User

	GetTOTPSecretKey() string
	PutTOTPSecretKey(string)
}

// UserOneTime allows totp codes to be one-time use only
type UserOneTime interface {
	User

	GetTOTPLastCode() string
	PutTOTPLastCode(string)
}

// TOTP implements time based one time passwords
type TOTP struct {
	*authboss.Authboss
}

// Setup the module
func (t *TOTP) Setup() error {
	var unauthedResponse authboss.MWRespondOnFailure
	if t.Config.Modules.ResponseOnUnauthed != 0 {
		unauthedResponse = t.Config.Modules.ResponseOnUnauthed
	} else if t.Config.Modules.RoutesRedirectOnUnauthed {
		unauthedResponse = authboss.RespondRedirect
	}
	abmw := authboss.MountedMiddleware2(t.Authboss, true, authboss.RequireFullAuth, unauthedResponse)

	var middleware, verified func(func(w http.ResponseWriter, r *http.Request) error) http.Handler
	middleware = func(handler func(http.ResponseWriter, *http.Request) error) http.Handler {
		return abmw(t.Core.ErrorHandler.Wrap(handler))
	}

	if t.Authboss.Config.Modules.TwoFactorEmailAuthRequired {
		setupPath := path.Join(t.Authboss.Paths.Mount, "/2fa/totp/setup")
		emailVerify, err := twofactor.SetupEmailVerify(t.Authboss, "totp", setupPath)
		if err != nil {
			return err
		}
		verified = func(handler func(http.ResponseWriter, *http.Request) error) http.Handler {
			return abmw(emailVerify.Wrap(t.Core.ErrorHandler.Wrap(handler)))
		}
	} else {
		verified = middleware
	}

	t.Authboss.Core.Router.Get("/2fa/totp/setup", verified(t.GetSetup))
	t.Authboss.Core.Router.Post("/2fa/totp/setup", verified(t.PostSetup))

	t.Authboss.Core.Router.Get("/2fa/totp/qr", verified(t.GetQRCode))

	t.Authboss.Core.Router.Get("/2fa/totp/confirm", verified(t.GetConfirm))
	t.Authboss.Core.Router.Post("/2fa/totp/confirm", verified(t.PostConfirm))

	t.Authboss.Core.Router.Get("/2fa/totp/remove", middleware(t.GetRemove))
	t.Authboss.Core.Router.Post("/2fa/totp/remove", middleware(t.PostRemove))

	t.Authboss.Core.Router.Get("/2fa/totp/validate", t.Core.ErrorHandler.Wrap(t.GetValidate))
	t.Authboss.Core.Router.Post("/2fa/totp/validate", t.Core.ErrorHandler.Wrap(t.PostValidate))

	t.Authboss.Events.Before(authboss.EventAuthHijack, t.HijackAuth)

	return t.Authboss.Core.ViewRenderer.Load(
		PageTOTPSetup,
		PageTOTPValidate,
		PageTOTPConfirm,
		PageTOTPConfirmSuccess,
		PageTOTPRemove,
		PageTOTPRemoveSuccess,
	)
}

// HijackAuth stores the user's pid in a special temporary session variable
// and redirects them to the validation endpoint.
func (t *TOTP) HijackAuth(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
	if handled {
		return false, nil
	}

	user := r.Context().Value(authboss.CTXKeyUser).(User)

	if len(user.GetTOTPSecretKey()) == 0 {
		return false, nil
	}

	authboss.PutSession(w, SessionTOTPPendingPID, user.GetPID())

	var query string
	if len(r.URL.RawQuery) != 0 {
		query = "?" + r.URL.RawQuery
	}
	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: t.Paths.Mount + "/2fa/totp/validate" + query,
	}
	return true, t.Authboss.Config.Core.Redirector.Redirect(w, r, ro)
}

// GetSetup shows a screen allows a user to opt in to setting up totp 2fa
func (t *TOTP) GetSetup(w http.ResponseWriter, r *http.Request) error {
	authboss.DelSession(w, SessionTOTPSecret)
	return t.Core.Responder.Respond(w, r, http.StatusOK, PageTOTPSetup, nil)
}

// PostSetup prepares adds a key to the user's session
func (t *TOTP) PostSetup(w http.ResponseWriter, r *http.Request) error {
	abUser, err := t.CurrentUser(r)
	if err != nil {
		return err
	}

	user := abUser.(User)

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      t.Authboss.Config.Modules.TOTP2FAIssuer,
		AccountName: user.GetEmail(),
	})
	if err != nil {
		return errors.Wrap(err, "failed to create a totp key")
	}

	secret := key.Secret()
	authboss.PutSession(w, SessionTOTPSecret, secret)

	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: t.Paths.Mount + "/2fa/totp/confirm",
	}
	return t.Core.Redirector.Redirect(w, r, ro)
}

// GetQRCode responds with a QR code image
func (t *TOTP) GetQRCode(w http.ResponseWriter, r *http.Request) error {
	abUser, err := t.CurrentUser(r)
	if err != nil {
		return err
	}
	user := abUser.(User)

	totpSecret, ok := authboss.GetSession(r, SessionTOTPSecret)

	var key *otp.Key
	if !ok || len(totpSecret) == 0 {
		totpSecret = user.GetTOTPSecretKey()
	}

	if len(totpSecret) == 0 {
		return errors.New("no totp secret found")
	}

	key, err = otp.NewKeyFromURL(
		fmt.Sprintf(otpKeyFormat,
			url.PathEscape(t.Authboss.Config.Modules.TOTP2FAIssuer),
			url.PathEscape(user.GetEmail()),
			url.QueryEscape(t.Authboss.Config.Modules.TOTP2FAIssuer),
			url.QueryEscape(totpSecret),
		))

	if err != nil {
		return errors.Wrap(err, "failed to reconstruct key from session key: %s")
	}

	image, err := key.Image(200, 200)
	if err != nil {
		return errors.Wrap(err, "failed to create totp qr code")
	}

	buf := &bytes.Buffer{}
	if err = png.Encode(buf, image); err != nil {
		return errors.Wrap(err, "failed to encode qr code to png")
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "image/png")
	w.WriteHeader(http.StatusOK)
	_, err = io.Copy(w, buf)
	return err
}

// GetConfirm requests a user to enter their totp code
func (t *TOTP) GetConfirm(w http.ResponseWriter, r *http.Request) error {
	totpSecret, ok := authboss.GetSession(r, SessionTOTPSecret)
	if !ok {
		return errors.New("request failed, no totp secret present in session")
	}

	data := authboss.HTMLData{DataTOTPSecret: totpSecret}
	return t.Core.Responder.Respond(w, r, http.StatusOK, PageTOTPConfirm, data)
}

// PostConfirm finally activates totp if the code matches
func (t *TOTP) PostConfirm(w http.ResponseWriter, r *http.Request) error {
	abUser, err := t.CurrentUser(r)
	if err != nil {
		return err
	}
	user := abUser.(User)

	totpSecret, ok := authboss.GetSession(r, SessionTOTPSecret)
	if !ok {
		return errors.New("request failed, no totp secret present in session")
	}

	validator, err := t.Authboss.Config.Core.BodyReader.Read(PageTOTPConfirm, r)
	if err != nil {
		return err
	}

	totpCodeValues := MustHaveTOTPCodeValues(validator)
	inputCode := totpCodeValues.GetCode()

	ok = totp.Validate(inputCode, totpSecret)
	if !ok {
		data := authboss.HTMLData{
			authboss.DataValidation: map[string][]string{FormValueCode: {
				t.Localizef(r.Context(), authboss.TxtInvalid2FACode),
			}},
			DataTOTPSecret: totpSecret,
		}
		return t.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageTOTPConfirm, data)
	}

	codes, err := twofactor.GenerateRecoveryCodes()
	if err != nil {
		return err
	}

	crypted, err := twofactor.BCryptRecoveryCodes(codes)
	if err != nil {
		return err
	}

	// Save the user which activates 2fa
	user.PutTOTPSecretKey(totpSecret)
	user.PutRecoveryCodes(twofactor.EncodeRecoveryCodes(crypted))
	if oneTime, ok := user.(UserOneTime); ok {
		oneTime.PutTOTPLastCode(inputCode)
	}
	if err = t.Authboss.Config.Storage.Server.Save(r.Context(), user); err != nil {
		return err
	}

	authboss.DelSession(w, SessionTOTPSecret)
	authboss.DelSession(w, authboss.Session2FAAuthed)

	logger := t.RequestLogger(r)
	logger.Infof("user %s enabled totp 2fa", user.GetPID())

	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
	if handled, err := t.Authboss.Events.FireAfter(authboss.EventTwoFactorAdded, w, r); err != nil {
		return err
	} else if handled {
		return nil
	}

	data := authboss.HTMLData{twofactor.DataRecoveryCodes: codes}
	return t.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageTOTPConfirmSuccess, data)
}

// GetRemove starts removal
func (t *TOTP) GetRemove(w http.ResponseWriter, r *http.Request) error {
	return t.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageTOTPRemove, nil)
}

// PostRemove removes totp
func (t *TOTP) PostRemove(w http.ResponseWriter, r *http.Request) error {
	logger := t.RequestLogger(r)

	user, status, err := t.validate(r)
	switch {
	case err == errNoTOTPEnabled:
		data := authboss.HTMLData{authboss.DataErr: t.Localizef(r.Context(), authboss.TxtTOTP2FANotActive)}
		return t.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageTOTPRemove, data)
	case err != nil:
		return err
	case status != t.Localizef(r.Context(), authboss.TxtSuccess):
		logger.Infof("user %s totp 2fa removal failure (%s)", user.GetPID(), status)
		data := authboss.HTMLData{
			authboss.DataValidation: map[string][]string{FormValueCode: {status}},
		}
		return t.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageTOTPRemove, data)
	}

	authboss.DelSession(w, authboss.Session2FA)
	user.PutTOTPSecretKey("")
	if err = t.Authboss.Config.Storage.Server.Save(r.Context(), user); err != nil {
		return err
	}

	logger.Infof("user %s disabled totp 2fa", user.GetPID())

	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
	if handled, err := t.Authboss.Events.FireAfter(authboss.EventTwoFactorRemoved, w, r); err != nil {
		return err
	} else if handled {
		return nil
	}

	return t.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageTOTPRemoveSuccess, nil)
}

// GetValidate shows a page to enter a code into
func (t *TOTP) GetValidate(w http.ResponseWriter, r *http.Request) error {
	return t.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageTOTPValidate, nil)
}

// PostValidate redirects on success
func (t *TOTP) PostValidate(w http.ResponseWriter, r *http.Request) error {
	logger := t.RequestLogger(r)

	user, status, err := t.validate(r)
	switch {
	case err == errNoTOTPEnabled:
		logger.Infof("user %s totp failure (not enabled)", user.GetPID())
		data := authboss.HTMLData{authboss.DataErr: t.Localizef(
			r.Context(), authboss.TxtTOTP2FANotActive)}
		return t.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageTOTPValidate, data)
	case err != nil:
		return err
	case status != t.Localizef(r.Context(), authboss.TxtSuccess):
		r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
		handled, err := t.Authboss.Events.FireAfter(authboss.EventAuthFail, w, r)
		if err != nil {
			return err
		} else if handled {
			return nil
		}

		logger.Infof("user %s totp 2fa failure (%s)", user.GetPID(), status)
		data := authboss.HTMLData{
			authboss.DataValidation: map[string][]string{FormValueCode: {status}},
		}
		return t.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageTOTPValidate, data)
	}

	// In the case where we care about re-using codes, validate will have set
	// this and we need to preserve it. Normally there's no database hit
	// required because we are only reading the secret and validating.
	if _, ok := user.(UserOneTime); ok {
		if err = t.Authboss.Config.Storage.Server.Save(r.Context(), user); err != nil {
			return err
		}
	}

	authboss.PutSession(w, authboss.SessionKey, user.GetPID())
	authboss.PutSession(w, authboss.Session2FA, "totp")

	authboss.DelSession(w, authboss.SessionHalfAuthKey)
	authboss.DelSession(w, SessionTOTPPendingPID)
	authboss.DelSession(w, SessionTOTPSecret)

	logger.Infof("user %s totp 2fa success", user.GetPID())

	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
	handled, err := t.Authboss.Events.FireAfter(authboss.EventAuth, w, r)
	if err != nil {
		return err
	} else if handled {
		return nil
	}

	ro := authboss.RedirectOptions{
		Code:             http.StatusTemporaryRedirect,
		RedirectPath:     t.Authboss.Config.Paths.AuthLoginOK,
		FollowRedirParam: true,
	}
	return t.Authboss.Core.Redirector.Redirect(w, r, ro)
}

// validate returns the user, a string representing a validation status (see
// validation* constants) and an error. The string return is completely invalid
// if err != nil.
//
// validate will set the previously used code to the input
func (t *TOTP) validate(r *http.Request) (User, string, error) {
	logger := t.RequestLogger(r)

	// Look up CurrentUser first, otherwise session persistence can allow
	// a previous login attempt's user to be recalled here by a logged in
	// user for 2fa removal and verification.
	abUser, err := t.CurrentUser(r)
	if err == authboss.ErrUserNotFound {
		pid, ok := authboss.GetSession(r, SessionTOTPPendingPID)
		if ok && len(pid) != 0 {
			abUser, err = t.Authboss.Config.Storage.Server.Load(r.Context(), pid)
		}
	}
	if err != nil {
		return nil, "", err
	}

	user := abUser.(User)

	secret := user.GetTOTPSecretKey()
	if len(secret) == 0 {
		return user, "", errNoTOTPEnabled
	}

	validator, err := t.Authboss.Config.Core.BodyReader.Read(PageTOTPValidate, r)
	if err != nil {
		return nil, "", err
	}

	totpCodeValues := MustHaveTOTPCodeValues(validator)

	if recoveryCode := totpCodeValues.GetRecoveryCode(); len(recoveryCode) != 0 {
		var ok bool
		recoveryCodes := twofactor.DecodeRecoveryCodes(user.GetRecoveryCodes())
		recoveryCodes, ok = twofactor.UseRecoveryCode(recoveryCodes, recoveryCode)

		if ok {
			logger.Infof("user %s used recovery code instead of sms2fa", user.GetPID())
			user.PutRecoveryCodes(twofactor.EncodeRecoveryCodes(recoveryCodes))
			if err := t.Authboss.Config.Storage.Server.Save(r.Context(), user); err != nil {
				return nil, "", err
			}
		} else {
			return user, t.Localizef(r.Context(), authboss.TxtInvalid2FACode), nil
		}

		return user, t.Localizef(r.Context(), authboss.TxtSuccess), nil
	}

	input := totpCodeValues.GetCode()

	if oneTime, ok := user.(UserOneTime); ok {
		oldCode := oneTime.GetTOTPLastCode()
		if oldCode == input {
			return user, t.Localizef(r.Context(), authboss.TxtRepeated2FACode), nil
		}
		oneTime.PutTOTPLastCode(input)
	}

	if !totp.Validate(input, secret) {
		return user, t.Localizef(r.Context(), authboss.TxtInvalid2FACode), nil
	}

	return user, t.Localizef(r.Context(), authboss.TxtSuccess), nil
}
