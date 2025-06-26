package twofactor

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"

	"github.com/aarondl/authboss/v3"
)

// EmailVerify has a middleware function that prevents access to routes
// unless e-mail has been verified.
//
// It does this by first setting where the user is coming from and generating
// an e-mail with a random token. The token is stored in the session.
//
// When the user clicks the e-mail link with the token, the token is confirmed
// by this middleware and the user is forwarded to the e-mail auth redirect.
type EmailVerify struct {
	*authboss.Authboss

	TwofactorKind     string
	TwofactorSetupURL string
}

// SetupEmailVerify registers routes for a particular 2fa method
func SetupEmailVerify(ab *authboss.Authboss, twofactorKind, setupURL string) (EmailVerify, error) {
	e := EmailVerify{
		Authboss:          ab,
		TwofactorKind:     twofactorKind,
		TwofactorSetupURL: setupURL,
	}

	var unauthedResponse authboss.MWRespondOnFailure
	if ab.Config.Modules.ResponseOnUnauthed != 0 {
		unauthedResponse = ab.Config.Modules.ResponseOnUnauthed
	} else if ab.Config.Modules.RoutesRedirectOnUnauthed {
		unauthedResponse = authboss.RespondRedirect
	}
	middleware := authboss.MountedMiddleware2(ab, true, authboss.RequireFullAuth, unauthedResponse)
	e.Authboss.Core.Router.Get("/2fa/"+twofactorKind+"/email/verify", middleware(ab.Core.ErrorHandler.Wrap(e.GetStart)))
	e.Authboss.Core.Router.Post("/2fa/"+twofactorKind+"/email/verify", middleware(ab.Core.ErrorHandler.Wrap(e.PostStart)))

	var routerMethod func(string, http.Handler)
	switch ab.Config.Modules.MailRouteMethod {
	case http.MethodGet:
		routerMethod = ab.Core.Router.Get
	case http.MethodPost:
		routerMethod = ab.Core.Router.Post
	default:
		return e, errors.New("MailRouteMethod must be set to something in the config")
	}
	routerMethod("/2fa/"+twofactorKind+"/email/verify/end", middleware(ab.Core.ErrorHandler.Wrap(e.End)))

	if err := e.Authboss.Core.ViewRenderer.Load(PageVerify2FA); err != nil {
		return e, err
	}

	return e, e.Authboss.Core.MailRenderer.Load(EmailVerifyHTML, EmailVerifyTxt)
}

// GetStart shows the e-mail address and asks you to confirm that you would
// like to proceed.
func (e EmailVerify) GetStart(w http.ResponseWriter, r *http.Request) error {
	cu, err := e.Authboss.CurrentUser(r)
	if err != nil {
		return err
	}

	user := cu.(User)

	data := authboss.HTMLData{
		DataVerifyEmail: user.GetEmail(),
		DataVerifyURL:   path.Join(e.Authboss.Paths.Mount, "2fa", e.TwofactorKind, "email/verify"),
	}
	return e.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageVerify2FA, data)
}

// PostStart sends an e-mail and shoves the user's token into the session
func (e EmailVerify) PostStart(w http.ResponseWriter, r *http.Request) error {
	cu, err := e.Authboss.CurrentUser(r)
	if err != nil {
		return err
	}

	user := cu.(User)
	ctx := r.Context()
	logger := e.Authboss.Logger(ctx)

	token, err := GenerateToken()
	if err != nil {
		return err
	}

	authboss.PutSession(w, authboss.Session2FAAuthToken, token)
	logger.Infof("generated new 2fa e-mail verify token for user: %s", user.GetPID())
	if e.Authboss.Config.Modules.MailNoGoroutine {
		e.SendVerifyEmail(ctx, user.GetEmail(), token)
	} else {
		go e.SendVerifyEmail(ctx, user.GetEmail(), token)
	}

	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: e.Authboss.Config.Paths.TwoFactorEmailAuthNotOK,
		Success:      e.Localizef(ctx, authboss.TxtEmailVerifyTriggered),
	}
	return e.Authboss.Config.Core.Redirector.Redirect(w, r, ro)
}

// SendVerifyEmail to the user
func (e EmailVerify) SendVerifyEmail(ctx context.Context, to, token string) {
	logger := e.Authboss.Logger(ctx)

	mailURL := e.mailURL(token)

	email := authboss.Email{
		To:       []string{to},
		From:     e.Config.Mail.From,
		FromName: e.Config.Mail.FromName,
		Subject:  e.Config.Mail.SubjectPrefix + e.Localizef(ctx, authboss.TxtEmailVerifySubject),
	}

	logger.Infof("sending add 2fa verification e-mail to: %s", to)

	ro := authboss.EmailResponseOptions{
		Data:         authboss.NewHTMLData(DataVerifyURL, mailURL),
		HTMLTemplate: EmailVerifyHTML,
		TextTemplate: EmailVerifyTxt,
	}
	if err := e.Authboss.Email(ctx, email, ro); err != nil {
		logger.Errorf("failed to send 2fa verification e-mail to %s: %+v", to, err)
	}
}

func (e EmailVerify) mailURL(token string) string {
	query := url.Values{FormValueToken: []string{token}}

	if len(e.Config.Mail.RootURL) != 0 {
		return fmt.Sprintf("%s?%s",
			e.Config.Mail.RootURL+"/2fa/"+e.TwofactorKind+"/email/verify/end",
			query.Encode())
	}

	p := path.Join(e.Config.Paths.Mount, "/2fa/"+e.TwofactorKind+"/email/verify/end")
	return fmt.Sprintf("%s%s?%s", e.Config.Paths.RootURL, p, query.Encode())
}

// End confirms the token passed in by the user (by the link in the e-mail)
func (e EmailVerify) End(w http.ResponseWriter, r *http.Request) error {
	values, err := e.Authboss.Core.BodyReader.Read(PageVerifyEnd2FA, r)
	if err != nil {
		return err
	}

	tokenValues := MustHaveEmailVerifyTokenValues(values)
	wantToken := tokenValues.GetToken()

	givenToken, _ := authboss.GetSession(r, authboss.Session2FAAuthToken)

	if 1 != subtle.ConstantTimeCompare([]byte(wantToken), []byte(givenToken)) {
		ro := authboss.RedirectOptions{
			Code:         http.StatusTemporaryRedirect,
			Failure:      e.Localizef(r.Context(), authboss.TxtInvalid2FAVerificationToken),
			RedirectPath: e.Authboss.Config.Paths.TwoFactorEmailAuthNotOK,
		}
		return e.Authboss.Core.Redirector.Redirect(w, r, ro)
	}

	authboss.DelSession(w, authboss.Session2FAAuthToken)
	authboss.PutSession(w, authboss.Session2FAAuthed, "true")

	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: e.TwofactorSetupURL,
	}
	return e.Authboss.Core.Redirector.Redirect(w, r, ro)
}

// Wrap a route and stop it from being accessed unless the Session2FAAuthed
// session value is "true".
func (e EmailVerify) Wrap(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !e.Authboss.Config.Modules.TwoFactorEmailAuthRequired {
			handler.ServeHTTP(w, r)
			return
		}

		// If this value exists the user's already verified
		authed, _ := authboss.GetSession(r, authboss.Session2FAAuthed)
		if authed == "true" {
			handler.ServeHTTP(w, r)
			return
		}

		redirURL := path.Join(e.Authboss.Config.Paths.Mount, "2fa", e.TwofactorKind, "email/verify")
		ro := authboss.RedirectOptions{
			Code:         http.StatusTemporaryRedirect,
			Failure:      e.Localizef(r.Context(), authboss.Txt2FAAuthorizationRequired),
			RedirectPath: redirURL,
		}

		if err := e.Authboss.Core.Redirector.Redirect(w, r, ro); err != nil {
			logger := e.Authboss.RequestLogger(r)
			logger.Errorf("failed to redirect client: %+v", err)
			return
		}
	})
}

// EmailVerifyTokenValuer returns a token from the body
type EmailVerifyTokenValuer interface {
	authboss.Validator

	GetToken() string
}

// MustHaveEmailVerifyTokenValues upgrades a validatable set of values
// to ones specific to a user that needs to be recovered.
func MustHaveEmailVerifyTokenValues(v authboss.Validator) EmailVerifyTokenValuer {
	if u, ok := v.(EmailVerifyTokenValuer); ok {
		return u
	}

	panic(fmt.Sprintf("bodyreader returned a type that could not be upgraded to an EmailVerifyTokenValues: %T", v))
}

// GenerateToken used for authenticating e-mails for 2fa setup
func GenerateToken() (string, error) {
	rawToken := make([]byte, verifyEmailTokenSize)
	if _, err := io.ReadFull(rand.Reader, rawToken); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(rawToken), nil
}
