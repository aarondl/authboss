// Package recover implements password reset via e-mail.
package recover

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/aarondl/authboss/v3"
)

// Constants for templates etc.
const (
	DataRecoverToken = "recover_token"
	DataRecoverURL   = "recover_url"

	FormValueToken = "token"

	EmailRecoverHTML = "recover_html"
	EmailRecoverTxt  = "recover_txt"

	PageRecoverStart  = "recover_start"
	PageRecoverMiddle = "recover_middle"
	PageRecoverEnd    = "recover_end"
)

func init() {
	m := &Recover{}
	authboss.RegisterModule("recover", m)
}

// Recover module
type Recover struct {
	*authboss.Authboss
}

// Init module
func (r *Recover) Init(ab *authboss.Authboss) (err error) {
	r.Authboss = ab

	if err := r.Config.Core.ViewRenderer.Load(PageRecoverStart, PageRecoverEnd); err != nil {
		return err
	}

	if err := r.Config.Core.MailRenderer.Load(EmailRecoverHTML, EmailRecoverTxt); err != nil {
		return err
	}

	r.Config.Core.Router.Get("/recover", r.Core.ErrorHandler.Wrap(r.StartGet))
	r.Config.Core.Router.Post("/recover", r.Core.ErrorHandler.Wrap(r.StartPost))
	r.Config.Core.Router.Get("/recover/end", r.Core.ErrorHandler.Wrap(r.EndGet))
	r.Config.Core.Router.Post("/recover/end", r.Core.ErrorHandler.Wrap(r.EndPost))

	return nil
}

// StartGet starts the recover procedure by rendering a form for the user.
func (r *Recover) StartGet(w http.ResponseWriter, req *http.Request) error {
	return r.Config.Core.Responder.Respond(w, req, http.StatusOK, PageRecoverStart, nil)
}

// StartPost starts the recover procedure using values provided from the user
// usually from the StartGet's form.
func (r *Recover) StartPost(w http.ResponseWriter, req *http.Request) error {
	logger := r.RequestLogger(req)

	validatable, err := r.Core.BodyReader.Read(PageRecoverStart, req)
	if err != nil {
		return err
	}

	if errs := validatable.Validate(); errs != nil {
		logger.Info("recover validation failed")
		data := authboss.HTMLData{authboss.DataValidation: authboss.ErrorMap(errs)}
		return r.Core.Responder.Respond(w, req, http.StatusOK, PageRecoverStart, data)
	}

	recoverVals := authboss.MustHaveRecoverStartValues(validatable)

	user, err := r.Storage.Server.Load(req.Context(), recoverVals.GetPID())
	if err == authboss.ErrUserNotFound {
		logger.Infof("user %s was attempted to be recovered, user does not exist, faking successful response", recoverVals.GetPID())
		ro := authboss.RedirectOptions{
			Code:         http.StatusTemporaryRedirect,
			RedirectPath: r.Config.Paths.RecoverOK,
			Success:      r.Localizef(req.Context(), authboss.TxtRecoverInitiateSuccessFlash),
		}
		return r.Core.Redirector.Redirect(w, req, ro)
	}

	ru := authboss.MustBeRecoverable(user)

	req = req.WithContext(context.WithValue(req.Context(), authboss.CTXKeyUser, user))
	handled, err := r.Events.FireBefore(authboss.EventRecoverStart, w, req)
	if err != nil {
		return err
	} else if handled {
		return nil
	}

	selector, verifier, token, err := r.Config.Core.OneTimeTokenGenerator.GenerateToken()
	if err != nil {
		return err
	}

	ruWithSecondaries, hasSecondaryEmails := authboss.CanBeRecoverableUserWithSecondaryEmails(user)

	ru.PutRecoverSelector(selector)
	ru.PutRecoverVerifier(verifier)
	ru.PutRecoverExpiry(time.Now().UTC().Add(r.Config.Modules.RecoverTokenDuration))

	if err := r.Storage.Server.Save(req.Context(), ru); err != nil {
		return err
	}

	recoveryEmailRecipients := []string{ru.GetEmail()}

	if hasSecondaryEmails {
		recoveryEmailRecipients = append(recoveryEmailRecipients, ruWithSecondaries.GetSecondaryEmails()...)
	}

	if r.Modules.MailNoGoroutine {
		r.SendRecoverEmail(req.Context(), recoveryEmailRecipients, token)
	} else {
		go r.SendRecoverEmail(req.Context(), recoveryEmailRecipients, token)
	}

	_, err = r.Events.FireAfter(authboss.EventRecoverStart, w, req)
	if err != nil {
		return err
	}

	logger.Infof("user %s password recovery initiated", ru.GetPID())
	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: r.Config.Paths.RecoverOK,
		Success:      r.Localizef(req.Context(), authboss.TxtRecoverInitiateSuccessFlash),
	}
	return r.Core.Redirector.Redirect(w, req, ro)
}

// SendRecoverEmail to a specific e-mail address passing along the encodedToken
// in an escaped URL to the templates.
func (r *Recover) SendRecoverEmail(ctx context.Context, to []string, encodedToken string) {
	logger := r.Logger(ctx)

	mailURL := r.mailURL(encodedToken)

	email := authboss.Email{
		To:       to,
		From:     r.Config.Mail.From,
		FromName: r.Config.Mail.FromName,
		Subject:  r.Config.Mail.SubjectPrefix + r.Localizef(ctx, authboss.TxtPasswordResetEmailSubject),
	}

	ro := authboss.EmailResponseOptions{
		HTMLTemplate: EmailRecoverHTML,
		TextTemplate: EmailRecoverTxt,
		Data: authboss.HTMLData{
			DataRecoverURL: mailURL,
		},
	}

	logger.Infof("sending recover e-mail to: %s", to)
	if err := r.Email(ctx, email, ro); err != nil {
		logger.Errorf("failed to recover send e-mail to %s: %+v", to, err)
	}
}

// EndGet shows a password recovery form, and it should have the token that
// the user brought in the query parameters in it on submission.
func (r *Recover) EndGet(w http.ResponseWriter, req *http.Request) error {
	validatable, err := r.Core.BodyReader.Read(PageRecoverMiddle, req)
	if err != nil {
		return err
	}

	values := authboss.MustHaveRecoverMiddleValues(validatable)
	token := values.GetToken()

	data := authboss.HTMLData{
		DataRecoverToken: token,
	}

	return r.Config.Core.Responder.Respond(w, req, http.StatusOK, PageRecoverEnd, data)
}

// EndPost retrieves the token
func (r *Recover) EndPost(w http.ResponseWriter, req *http.Request) error {
	logger := r.RequestLogger(req)

	validatable, err := r.Core.BodyReader.Read(PageRecoverEnd, req)
	if err != nil {
		return err
	}

	values := authboss.MustHaveRecoverEndValues(validatable)
	password := values.GetPassword()
	token := values.GetToken()

	if errs := validatable.Validate(); errs != nil {
		logger.Info("recovery validation failed")
		data := authboss.HTMLData{
			authboss.DataValidation: authboss.ErrorMap(errs),
			DataRecoverToken:        token,
		}
		return r.Config.Core.Responder.Respond(w, req, http.StatusOK, PageRecoverEnd, data)
	}

	rawToken, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		logger.Infof("invalid recover token submitted, base64 decode failed: %+v", err)
		return r.invalidToken(PageRecoverEnd, w, req)
	}

	credsGenerator := r.Core.OneTimeTokenGenerator

	if len(rawToken) != credsGenerator.TokenSize() {
		logger.Infof("invalid recover token submitted, size was wrong: %d", len(rawToken))
		return r.invalidToken(PageRecoverEnd, w, req)
	}

	selectorBytes, verifierBytes := credsGenerator.ParseToken(string(rawToken))
	selector := base64.StdEncoding.EncodeToString(selectorBytes[:])

	storer := authboss.EnsureCanRecover(r.Config.Storage.Server)
	user, err := storer.LoadByRecoverSelector(req.Context(), selector)
	if err == authboss.ErrUserNotFound {
		logger.Info("invalid recover token submitted, user not found")
		return r.invalidToken(PageRecoverEnd, w, req)
	} else if err != nil {
		return err
	}

	if time.Now().UTC().After(user.GetRecoverExpiry()) {
		logger.Infof("invalid recover token submitted, already expired: %+v", err)
		return r.invalidToken(PageRecoverEnd, w, req)
	}

	dbVerifierBytes, err := base64.StdEncoding.DecodeString(user.GetRecoverVerifier())
	if err != nil {
		logger.Infof("invalid recover verifier stored in database: %s", user.GetRecoverVerifier())
		return r.invalidToken(PageRecoverEnd, w, req)
	}

	if subtle.ConstantTimeEq(int32(len(verifierBytes)), int32(len(dbVerifierBytes))) != 1 ||
		subtle.ConstantTimeCompare(verifierBytes[:], dbVerifierBytes) != 1 {
		logger.Info("stored recover verifier does not match provided one")
		return r.invalidToken(PageRecoverEnd, w, req)
	}

	req = req.WithContext(context.WithValue(req.Context(), authboss.CTXKeyUser, user))
	handled, err := r.Events.FireBefore(authboss.EventRecoverEnd, w, req)
	if err != nil {
		return err
	} else if handled {
		return nil
	}

	pass, err := r.Config.Core.Hasher.GenerateHash(password)
	if err != nil {
		return err
	}

	user.PutPassword(pass)
	user.PutRecoverSelector("")             // Don't allow another recovery
	user.PutRecoverVerifier("")             // Don't allow another recovery
	user.PutRecoverExpiry(time.Now().UTC()) // Put current time for those DBs that can't handle 0 time

	if err := storer.Save(req.Context(), user); err != nil {
		return err
	}

	_, err = r.Events.FireAfter(authboss.EventRecoverEnd, w, req)
	if err != nil {
		return err
	}

	successMsg := r.Localizef(req.Context(), authboss.TxtRecoverSuccessMsg)
	if r.Config.Modules.RecoverLoginAfterRecovery {
		handled, err = r.Events.FireBefore(authboss.EventAuth, w, req)
		if err != nil {
			return err
		} else if handled {
			return nil
		}

		handled, err = r.Events.FireBefore(authboss.EventAuthHijack, w, req)
		if err != nil {
			return err
		} else if handled {
			return nil
		}

		authboss.PutSession(w, authboss.SessionKey, user.GetPID())
		successMsg = r.Localizef(req.Context(), authboss.TxtRecoverAndLoginSuccessMsg)

		handled, err = r.Events.FireAfter(authboss.EventAuth, w, req)
		if err != nil {
			return err
		} else if handled {
			return nil
		}
	}

	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: r.Config.Paths.RecoverOK,
		Success:      successMsg,
	}
	return r.Config.Core.Redirector.Redirect(w, req, ro)
}

func (r *Recover) invalidToken(page string, w http.ResponseWriter, req *http.Request) error {
	errorsAll := []error{errors.New("recovery token is invalid")}
	data := authboss.HTMLData{authboss.DataValidation: authboss.ErrorMap(errorsAll)}
	return r.Core.Responder.Respond(w, req, http.StatusOK, PageRecoverEnd, data)
}

func (r *Recover) mailURL(token string) string {
	query := url.Values{FormValueToken: []string{token}}

	if len(r.Config.Mail.RootURL) != 0 {
		return fmt.Sprintf("%s?%s", r.Config.Mail.RootURL+"/recover/end", query.Encode())
	}

	p := path.Join(r.Config.Paths.Mount, "recover/end")
	return fmt.Sprintf("%s%s?%s", r.Config.Paths.RootURL, p, query.Encode())
}

// GenerateRecoverCreds generates pieces needed for user recovery
// selector: hash of the first half of a 64 byte value
// (to be stored in the database and used in SELECT query)
// verifier: hash of the second half of a 64 byte value
// (to be stored in database but never used in SELECT query)
// token: the user-facing base64 encoded selector+verifier
//
// Deprecated: Use [authboss.OneTimeTokenGenerator] instead.
func GenerateRecoverCreds() (selector, verifier, token string, err error) {
	recoverTokenSize := 64
	recoverTokenSplit := recoverTokenSize / 2

	rawToken := make([]byte, recoverTokenSize)
	if _, err = io.ReadFull(rand.Reader, rawToken); err != nil {
		return "", "", "", err
	}
	selectorBytes := sha512.Sum512(rawToken[:recoverTokenSplit])
	verifierBytes := sha512.Sum512(rawToken[recoverTokenSplit:])

	return base64.StdEncoding.EncodeToString(selectorBytes[:]),
		base64.StdEncoding.EncodeToString(verifierBytes[:]),
		base64.URLEncoding.EncodeToString(rawToken),
		nil
}
