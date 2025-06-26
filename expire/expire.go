// Package expire helps expire user's logged in sessions
package expire

import (
	"context"
	"net/http"
	"time"

	"github.com/aarondl/authboss/v3"
)

var nowTime = time.Now

// Setup the expire module
//
// This installs a hook into the login process so that the
// LastAction is recorded immediately.
func Setup(ab *authboss.Authboss) error {
	ab.Events.After(authboss.EventAuth, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
		refreshExpiry(w)
		return false, nil
	})

	return nil
}

// TimeToExpiry returns zero if the user session is expired else the time
// until expiry. Takes in the allowed idle duration.
func TimeToExpiry(r *http.Request, expireAfter time.Duration) time.Duration {
	return timeToExpiry(r, expireAfter)
}

func timeToExpiry(r *http.Request, expireAfter time.Duration) time.Duration {
	dateStr, ok := authboss.GetSession(r, authboss.SessionLastAction)
	if !ok {
		return expireAfter
	}

	date, err := time.Parse(time.RFC3339, dateStr)
	if err != nil {
		panic("last_action is not a valid RFC3339 date")
	}

	remaining := date.Add(expireAfter).Sub(nowTime().UTC())
	if remaining > 0 {
		return remaining
	}

	return 0
}

// RefreshExpiry updates the last action for the user, so he doesn't
// become expired.
func RefreshExpiry(w http.ResponseWriter, r *http.Request) {
	refreshExpiry(w)
}

func refreshExpiry(w http.ResponseWriter) {
	authboss.PutSession(w, authboss.SessionLastAction, nowTime().UTC().Format(time.RFC3339))
}

type expireMiddleware struct {
	expireAfter      time.Duration
	next             http.Handler
	sessionWhitelist []string
}

// Middleware ensures that the user's expiry information is kept up-to-date
// on each request. Deletes the SessionKey from the session if the user is
// expired (a.ExpireAfter duration since SessionLastAction).
// This middleware conflicts with use of the Remember module, don't enable both
// at the same time.
func Middleware(ab *authboss.Authboss) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return expireMiddleware{
			expireAfter:      ab.Config.Modules.ExpireAfter,
			next:             next,
			sessionWhitelist: ab.Config.Storage.SessionStateWhitelistKeys,
		}
	}
}

// ServeHTTP removes the session and hides the loaded user from the handlers
// below it.
func (m expireMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if _, ok := authboss.GetSession(r, authboss.SessionKey); ok {
		ttl := timeToExpiry(r, m.expireAfter)

		if ttl == 0 {
			authboss.DelAllSession(w, m.sessionWhitelist)
			authboss.DelSession(w, authboss.SessionKey)
			authboss.DelSession(w, authboss.SessionLastAction)
			ctx := context.WithValue(r.Context(), authboss.CTXKeyPID, nil)
			ctx = context.WithValue(ctx, authboss.CTXKeyUser, nil)

			ctxState := r.Context().Value(authboss.CTXKeySessionState)
			if ctxState != nil {
				state := ctxState.(authboss.ClientState)
				whitelist := make(map[string]struct{})

				for _, w := range m.sessionWhitelist {
					whitelist[w] = struct{}{}
				}

				newState := stateHider{cs: state, whitelist: whitelist}
				ctx = context.WithValue(ctx, authboss.CTXKeySessionState, newState)
			}

			r = r.WithContext(ctx)
		} else {
			refreshExpiry(w)
		}
	}

	m.next.ServeHTTP(w, r)
}

type stateHider struct {
	whitelist map[string]struct{}
	cs        authboss.ClientState
}

func (k stateHider) Get(s string) (string, bool) {
	_, ok := k.whitelist[s]
	if !ok {
		return "", false
	}

	return k.cs.Get(s)
}
