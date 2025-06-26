// Package remember implements persistent logins using cookies
package remember

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"io"
	"net/http"

	"github.com/friendsofgo/errors"
	"github.com/aarondl/authboss/v3"
)

const (
	nNonceSize = 32
)

func init() {
	authboss.RegisterModule("remember", &Remember{})
}

// Remember module
type Remember struct {
	*authboss.Authboss
}

// Init module
func (r *Remember) Init(ab *authboss.Authboss) error {
	r.Authboss = ab

	r.Events.After(authboss.EventAuth, r.RememberAfterAuth)
	r.Events.After(authboss.EventOAuth2, r.RememberAfterAuth)
	r.Events.After(authboss.EventRecoverEnd, r.AfterPasswordReset)

	return nil
}

// RememberAfterAuth creates a remember token and saves it in the user's cookies.
func (r *Remember) RememberAfterAuth(w http.ResponseWriter, req *http.Request, handled bool) (bool, error) {
	rmIntf := req.Context().Value(authboss.CTXKeyValues)
	if rmIntf == nil {
		return false, nil
	} else if rm, ok := rmIntf.(authboss.RememberValuer); !ok || !rm.GetShouldRemember() {
		return false, nil
	}

	user := r.Authboss.CurrentUserP(req)
	hash, token, err := GenerateToken(user.GetPID())
	if err != nil {
		return false, err
	}

	storer := authboss.EnsureCanRemember(r.Authboss.Config.Storage.Server)
	if err = storer.AddRememberToken(req.Context(), user.GetPID(), hash); err != nil {
		return false, err
	}

	authboss.PutCookie(w, authboss.CookieRemember, token)

	return false, nil
}

// Middleware automatically authenticates users if they have remember me tokens
// If the user has been loaded already, it returns early
func Middleware(ab *authboss.Authboss) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Safely can ignore error here
			if id, _ := ab.CurrentUserID(r); len(id) == 0 {
				if err := Authenticate(ab, w, &r); err != nil {
					logger := ab.RequestLogger(r)
					logger.Errorf("failed to authenticate user via remember me: %+v", err)
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Authenticate the user using their remember cookie.
// If the cookie proves unusable it will be deleted. A cookie
// may be unusable for the following reasons:
// - Can't decode the base64
// - Invalid token format
// - Can't find token in DB
//
// In order to authenticate it adds to the request context as well as to the
// cookie and session states.
func Authenticate(ab *authboss.Authboss, w http.ResponseWriter, req **http.Request) error {
	logger := ab.RequestLogger(*req)
	cookie, ok := authboss.GetCookie(*req, authboss.CookieRemember)
	if !ok {
		return nil
	}

	rawToken, err := base64.URLEncoding.DecodeString(cookie)
	if err != nil {
		authboss.DelCookie(w, authboss.CookieRemember)
		logger.Infof("failed to decode remember me cookie, deleting cookie")
		return nil
	}

	index := bytes.IndexByte(rawToken, ';')
	if index < 0 {
		authboss.DelCookie(w, authboss.CookieRemember)
		logger.Infof("failed to decode remember me token, deleting cookie")
		return nil
	}

	pid := string(rawToken[:index])
	sum := sha512.Sum512(rawToken)
	hash := base64.StdEncoding.EncodeToString(sum[:])

	storer := authboss.EnsureCanRemember(ab.Config.Storage.Server)
	err = storer.UseRememberToken((*req).Context(), pid, hash)
	switch {
	case err == authboss.ErrTokenNotFound:
		logger.Infof("remember me cookie had a token that was not in storage, deleting cookie")
		authboss.DelCookie(w, authboss.CookieRemember)
		return nil
	case err != nil:
		return err
	}

	hash, token, err := GenerateToken(pid)
	if err != nil {
		return err
	}

	if err = storer.AddRememberToken((*req).Context(), pid, hash); err != nil {
		return errors.Wrap(err, "failed to save remember me token")
	}

	*req = (*req).WithContext(context.WithValue((*req).Context(), authboss.CTXKeyPID, pid))
	authboss.PutSession(w, authboss.SessionKey, pid)
	authboss.PutSession(w, authboss.SessionHalfAuthKey, "true")
	authboss.DelCookie(w, authboss.CookieRemember)
	authboss.PutCookie(w, authboss.CookieRemember, token)

	return nil
}

// AfterPasswordReset is called after the password has been reset, since
// it should invalidate all tokens associated to that user.
func (r *Remember) AfterPasswordReset(w http.ResponseWriter, req *http.Request, handled bool) (bool, error) {
	user, err := r.Authboss.CurrentUser(req)
	if err != nil {
		return false, err
	}

	logger := r.Authboss.RequestLogger(req)
	storer := authboss.EnsureCanRemember(r.Authboss.Config.Storage.Server)

	pid := user.GetPID()
	authboss.DelCookie(w, authboss.CookieRemember)

	logger.Infof("deleting tokens and rm cookies for user %s due to password reset", pid)

	return false, storer.DelRememberTokens(req.Context(), pid)
}

// GenerateToken creates a remember me token
func GenerateToken(pid string) (hash string, token string, err error) {
	rawToken := make([]byte, nNonceSize+len(pid)+1)
	copy(rawToken, pid)
	rawToken[len(pid)] = ';'

	if _, err := io.ReadFull(rand.Reader, rawToken[len(pid)+1:]); err != nil {
		return "", "", errors.Wrap(err, "failed to create remember me nonce")
	}

	sum := sha512.Sum512(rawToken)
	return base64.StdEncoding.EncodeToString(sum[:]), base64.URLEncoding.EncodeToString(rawToken), nil
}
