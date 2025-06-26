// Package lock implements user locking after N bad sign-in attempts.
package lock

import (
	"context"
	"net/http"
	"time"

	"github.com/aarondl/authboss/v3"
)

// Storage key constants
const (
	StoreAttemptNumber = "attempt_number"
	StoreAttemptTime   = "attempt_time"
	StoreLocked        = "locked"
)

func init() {
	authboss.RegisterModule("lock", &Lock{})
}

// Lock module
type Lock struct {
	*authboss.Authboss
}

// Init the module
func (l *Lock) Init(ab *authboss.Authboss) error {
	l.Authboss = ab

	l.Events.Before(authboss.EventAuth, l.BeforeAuth)
	l.Events.Before(authboss.EventOAuth2, l.BeforeAuth)
	l.Events.After(authboss.EventAuth, l.AfterAuthSuccess)
	l.Events.After(authboss.EventAuthFail, l.AfterAuthFail)

	return nil
}

// BeforeAuth ensures the account is not locked.
func (l *Lock) BeforeAuth(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
	return l.updateLockedState(w, r, true)
}

// AfterAuthSuccess resets the attempt number field.
func (l *Lock) AfterAuthSuccess(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
	user, err := l.Authboss.CurrentUser(r)
	if err != nil {
		return false, err
	}

	lu := authboss.MustBeLockable(user)
	lu.PutAttemptCount(0)
	lu.PutLastAttempt(time.Now().UTC())

	return false, l.Authboss.Config.Storage.Server.Save(r.Context(), lu)
}

// AfterAuthFail adjusts the attempt number and time negatively
// and locks the user if they're beyond limits.
func (l *Lock) AfterAuthFail(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
	return l.updateLockedState(w, r, false)
}

// updateLockedState exists to minimize any differences between a success and
// a failure path in the case where a correct/incorrect password is entered
func (l *Lock) updateLockedState(w http.ResponseWriter, r *http.Request, wasCorrectPassword bool) (bool, error) {
	user, err := l.Authboss.CurrentUser(r)
	if err != nil {
		return false, err
	}

	// Fetch things
	lu := authboss.MustBeLockable(user)
	last := lu.GetLastAttempt()
	attempts := lu.GetAttemptCount()
	attempts++

	if !wasCorrectPassword {
		if time.Now().UTC().Sub(last) <= l.Modules.LockWindow {
			if attempts >= l.Modules.LockAfter {
				lu.PutLocked(time.Now().UTC().Add(l.Modules.LockDuration))
			}

			lu.PutAttemptCount(attempts)
		} else {
			lu.PutAttemptCount(1)
		}
	}
	lu.PutLastAttempt(time.Now().UTC())

	if err := l.Authboss.Config.Storage.Server.Save(r.Context(), lu); err != nil {
		return false, err
	}

	if !IsLocked(lu) {
		return false, nil
	}

	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		Failure:      l.Localizef(r.Context(), authboss.TxtLocked),
		RedirectPath: l.Authboss.Config.Paths.LockNotOK,
	}
	return true, l.Authboss.Config.Core.Redirector.Redirect(w, r, ro)
}

// Lock a user manually.
func (l *Lock) Lock(ctx context.Context, key string) error {
	user, err := l.Authboss.Config.Storage.Server.Load(ctx, key)
	if err != nil {
		return err
	}

	lu := authboss.MustBeLockable(user)
	lu.PutLocked(time.Now().UTC().Add(l.Authboss.Config.Modules.LockDuration))

	return l.Authboss.Config.Storage.Server.Save(ctx, lu)
}

// Unlock a user that was locked by this module.
func (l *Lock) Unlock(ctx context.Context, key string) error {
	user, err := l.Authboss.Config.Storage.Server.Load(ctx, key)
	if err != nil {
		return err
	}

	lu := authboss.MustBeLockable(user)

	// Set the last attempt to be -window*2 to avoid immediately
	// giving another login failure. Don't reset Locked to Zero time
	// because some databases may have trouble storing values before
	// unix_time(0): Jan 1st, 1970
	now := time.Now().UTC()
	lu.PutAttemptCount(0)
	lu.PutLastAttempt(now.Add(-l.Authboss.Config.Modules.LockWindow * 2))
	lu.PutLocked(now.Add(-l.Authboss.Config.Modules.LockDuration))

	return l.Authboss.Config.Storage.Server.Save(ctx, lu)
}

// Middleware ensures that a user is not locked, or else it will intercept
// the request and send them to the configured LockNotOK page, this will load
// the user if he's not been loaded yet from the session. And panics if it
// cannot load the user.
func Middleware(ab *authboss.Authboss) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := ab.LoadCurrentUserP(&r)

			lu := authboss.MustBeLockable(user)
			if !IsLocked(lu) {
				next.ServeHTTP(w, r)
				return
			}

			logger := ab.RequestLogger(r)
			logger.Infof("user %s prevented from accessing %s: locked", user.GetPID(), r.URL.Path)
			ro := authboss.RedirectOptions{
				Code:         http.StatusTemporaryRedirect,
				Failure:      ab.Localizef(r.Context(), authboss.TxtLocked),
				RedirectPath: ab.Config.Paths.LockNotOK,
			}
			if err := ab.Config.Core.Redirector.Redirect(w, r, ro); err != nil {
				logger.Errorf("error redirecting in lock.Middleware: #%v", err)
			}
		})
	}
}

// IsLocked checks if a user is locked
func IsLocked(lu authboss.LockableUser) bool {
	return lu.GetLocked().After(time.Now().UTC())
}
