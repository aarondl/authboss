// Package auth implements password based user logins.
package auth

import (
	"context"
	"net/http"

	"github.com/aarondl/authboss/v3"
)

const (
	// PageLogin is for identifying the login page for parsing & validation
	PageLogin = "login"
)

func init() {
	authboss.RegisterModule("auth", &Auth{})
}

// Auth module
type Auth struct {
	*authboss.Authboss
}

// Init module
func (a *Auth) Init(ab *authboss.Authboss) (err error) {
	a.Authboss = ab

	if err = a.Authboss.Config.Core.ViewRenderer.Load(PageLogin); err != nil {
		return err
	}

	a.Authboss.Config.Core.Router.Get("/login", a.Authboss.Core.ErrorHandler.Wrap(a.LoginGet))
	a.Authboss.Config.Core.Router.Post("/login", a.Authboss.Core.ErrorHandler.Wrap(a.LoginPost))

	return nil
}

// LoginGet simply displays the login form
func (a *Auth) LoginGet(w http.ResponseWriter, r *http.Request) error {
	data := authboss.HTMLData{}
	if redir := r.URL.Query().Get(authboss.FormValueRedirect); len(redir) != 0 {
		data[authboss.FormValueRedirect] = redir
	}
	return a.Core.Responder.Respond(w, r, http.StatusOK, PageLogin, data)
}

// LoginPost attempts to validate the credentials passed in
// to log in a user.
func (a *Auth) LoginPost(w http.ResponseWriter, r *http.Request) error {
	logger := a.RequestLogger(r)

	validatable, err := a.Authboss.Core.BodyReader.Read(PageLogin, r)
	if err != nil {
		return err
	}

	// Skip validation since all the validation happens during the database lookup and
	// password check.
	creds := authboss.MustHaveUserValues(validatable)

	pid := creds.GetPID()
	pidUser, err := a.Authboss.Storage.Server.Load(r.Context(), pid)
	if err == authboss.ErrUserNotFound {
		logger.Infof("failed to load user requested by pid: %s", pid)
		data := authboss.HTMLData{authboss.DataErr: a.Localizef(r.Context(), authboss.TxtInvalidCredentials)}
		return a.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageLogin, data)
	} else if err != nil {
		return err
	}

	authUser := authboss.MustBeAuthable(pidUser)
	password := authUser.GetPassword()

	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, pidUser))

	var handled bool
	err = a.Authboss.Core.Hasher.CompareHashAndPassword(password, creds.GetPassword())
	if err != nil {
		handled, err = a.Authboss.Events.FireAfter(authboss.EventAuthFail, w, r)
		if err != nil {
			return err
		} else if handled {
			return nil
		}

		logger.Infof("user %s failed to log in", pid)
		data := authboss.HTMLData{authboss.DataErr: a.Localizef(r.Context(), authboss.TxtInvalidCredentials)}
		return a.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageLogin, data)
	}

	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyValues, validatable))

	handled, err = a.Events.FireBefore(authboss.EventAuth, w, r)
	if err != nil {
		return err
	} else if handled {
		return nil
	}

	handled, err = a.Events.FireBefore(authboss.EventAuthHijack, w, r)
	if err != nil {
		return err
	} else if handled {
		return nil
	}

	logger.Infof("user %s logged in", pid)
	authboss.PutSession(w, authboss.SessionKey, pid)
	authboss.DelSession(w, authboss.SessionHalfAuthKey)

	handled, err = a.Authboss.Events.FireAfter(authboss.EventAuth, w, r)
	if err != nil {
		return err
	} else if handled {
		return nil
	}

	ro := authboss.RedirectOptions{
		Code:             http.StatusTemporaryRedirect,
		RedirectPath:     a.Authboss.Paths.AuthLoginOK,
		FollowRedirParam: true,
	}
	return a.Authboss.Core.Redirector.Redirect(w, r, ro)
}
