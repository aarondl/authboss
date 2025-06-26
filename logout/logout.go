// Package logout allows users to log out (from auth or oauth2 logins)
package logout

import (
	"net/http"

	"github.com/friendsofgo/errors"
	"github.com/aarondl/authboss/v3"
)

func init() {
	authboss.RegisterModule("logout", &Logout{})
}

// Logout module
type Logout struct {
	*authboss.Authboss
}

// Init the module
func (l *Logout) Init(ab *authboss.Authboss) error {
	l.Authboss = ab

	var logoutRouteMethod func(string, http.Handler)
	switch l.Config.Modules.LogoutMethod {
	case "GET":
		logoutRouteMethod = l.Config.Core.Router.Get
	case "POST":
		logoutRouteMethod = l.Config.Core.Router.Post
	case "DELETE":
		logoutRouteMethod = l.Config.Core.Router.Delete
	default:
		return errors.Errorf("logout wants to register a logout route but was given an invalid method: %s", l.Config.Modules.LogoutMethod)
	}

	logoutRouteMethod("/logout", l.Core.ErrorHandler.Wrap(l.Logout))

	return nil
}

// Logout the user
func (l *Logout) Logout(w http.ResponseWriter, r *http.Request) error {
	logger := l.RequestLogger(r)

	user, err := l.CurrentUser(r)
	if err == nil && user != nil {
		logger.Infof("user %s logged out", user.GetPID())
	} else {
		logger.Info("user (unknown) logged out")
	}

	var handled bool
	handled, err = l.Events.FireBefore(authboss.EventLogout, w, r)
	if err != nil {
		return err
	} else if handled {
		return nil
	}

	authboss.DelAllSession(w, l.Config.Storage.SessionStateWhitelistKeys)
	authboss.DelKnownSession(w)
	authboss.DelKnownCookie(w)

	handled, err = l.Events.FireAfter(authboss.EventLogout, w, r)
	if err != nil {
		return err
	} else if handled {
		return nil
	}

	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: l.Paths.LogoutOK,
		Success:      l.Localizef(r.Context(), authboss.TxtLoggedOut),
	}
	return l.Core.Redirector.Redirect(w, r, ro)
}
