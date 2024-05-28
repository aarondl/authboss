// Package oauth2 allows users to be created and authenticated
// via oauth2 services like facebook, google etc. Currently
// only the web server flow is supported.
//
// The general flow looks like this:
//  1. User goes to Start handler and has his session packed with goodies
//     then redirects to the OAuth service.
//  2. OAuth service returns to OAuthCallback which extracts state and
//     parameters and generally checks that everything is ok. It uses the
//     token received to get an access token from the oauth2 library
//  3. Calls the OAuth2Provider.FindUserDetails which should return the user's
//     details in a generic form.
//  4. Passes the user details into the OAuth2ServerStorer.NewFromOAuth2 in
//     order to create a user object we can work with.
//  5. Saves the user in the database, logs them in, redirects.
//
// In order to do this there are a number of parts:
//  1. The configuration of a provider
//     (handled by authboss.Config.Modules.OAuth2Providers).
//  2. The flow of redirection of client, parameter passing etc
//     (handled by this package)
//  3. The HTTP call to the service once a token has been retrieved to
//     get user details (handled by OAuth2Provider.FindUserDetails)
//  4. The creation of a user from the user details returned from the
//     FindUserDetails (authboss.OAuth2ServerStorer)
//  5. The special casing of the ServerStorer implementation's Load()
//     function to deal properly with incoming OAuth2 pids. See
//     authboss.ParseOAuth2PID as a way to do this.
//
// Of these parts, the responsibility of the authboss library consumer
// is on 1, 3, 4, and 5. Configuration of providers that should be used is
// totally up to the consumer. The FindUserDetails function is typically up to
// the user, but we have some basic ones included in this package too.
// The creation of users from the FindUserDetail's map[string]string return
// is handled as part of the implementation of the OAuth2ServerStorer.
package oauth2

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/friendsofgo/errors"
	"golang.org/x/oauth2"

	"github.com/volatiletech/authboss/v3"
)

// FormValue constants
const (
	FormValueOAuth2State = "state"
	FormValueOAuth2Redir = "redir"
)

var errOAuthStateValidation = errors.New("could not validate oauth2 state param")

// OAuth2 module
type OAuth2 struct {
	*authboss.Authboss
}

func init() {
	authboss.RegisterModule("oauth2", &OAuth2{})
}

// Init module
func (o *OAuth2) Init(ab *authboss.Authboss) error {
	o.Authboss = ab

	// Do annoying sorting on keys so we can have predictable
	// route registration (both for consistency inside the router but
	// also for tests -_-)
	var keys []string
	for k := range o.Authboss.Config.Modules.OAuth2Providers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, provider := range keys {
		cfg := o.Authboss.Config.Modules.OAuth2Providers[provider]
		provider = strings.ToLower(provider)

		init := fmt.Sprintf("/oauth2/%s", provider)
		callback := fmt.Sprintf("/oauth2/callback/%s", provider)

		o.Authboss.Config.Core.Router.Get(init, o.Authboss.Core.ErrorHandler.Wrap(o.Start))
		o.Authboss.Config.Core.Router.Get(callback, o.Authboss.Core.ErrorHandler.Wrap(o.End))

		if mount := o.Authboss.Config.Paths.Mount; len(mount) > 0 {
			callback = path.Join(mount, callback)
		}

		cfg.OAuth2Config.RedirectURL = o.Authboss.Config.Paths.RootURL + callback
	}

	return nil
}

// Start the oauth2 process
func (o *OAuth2) Start(w http.ResponseWriter, r *http.Request) error {
	logger := o.Authboss.RequestLogger(r)

	provider := strings.ToLower(filepath.Base(r.URL.Path))
	logger.Infof("started oauth2 flow for provider: %s", provider)
	cfg, ok := o.Authboss.Config.Modules.OAuth2Providers[provider]
	if !ok {
		return errors.Errorf("oauth2 provider %q not found", provider)
	}

	// Create nonce
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return errors.Wrap(err, "failed to create nonce")
	}

	state := base64.URLEncoding.EncodeToString(nonce)
	authboss.PutSession(w, authboss.SessionOAuth2State, state)

	// This clearly ignores the fact that query parameters can have multiple
	// values but I guess we're ignoring that
	passAlongs := make(map[string]string)
	for k, vals := range r.URL.Query() {
		for _, val := range vals {
			passAlongs[k] = val
		}
	}

	if len(passAlongs) > 0 {
		byt, err := json.Marshal(passAlongs)
		if err != nil {
			return err
		}
		authboss.PutSession(w, authboss.SessionOAuth2Params, string(byt))
	} else {
		authboss.DelSession(w, authboss.SessionOAuth2Params)
	}
	overrideRediriectURI := r.URL.Query().Get("redirect_uri")
	oauthConfig := cfg.OAuth2Config
	if overrideRediriectURI != "" {
		// TODO will validates overrideRediriectURI by whitelisted WhitelistRedirectURIs []string
		oauthConfig = &oauth2.Config{
			ClientID:     cfg.OAuth2Config.ClientID,
			ClientSecret: cfg.OAuth2Config.ClientSecret,
			Endpoint:     cfg.OAuth2Config.Endpoint,
			RedirectURL:  overrideRediriectURI,
			Scopes:       cfg.OAuth2Config.Scopes,
		}
	}
	authCodeUrl := oauthConfig.AuthCodeURL(state)

	extraParams := cfg.AdditionalParams.Encode()
	if len(extraParams) > 0 {
		authCodeUrl = fmt.Sprintf("%s&%s", authCodeUrl, extraParams)
	}

	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: authCodeUrl,
	}
	return o.Authboss.Core.Redirector.Redirect(w, r, ro)
}

// for testing, mocked out at the beginning
var exchanger = (*oauth2.Config).Exchange

// End the oauth2 process, this is the handler for the oauth2 callback
// that the third party will redirect to.
func (o *OAuth2) End(w http.ResponseWriter, r *http.Request) error {
	logger := o.Authboss.RequestLogger(r)
	provider := strings.ToLower(filepath.Base(r.URL.Path))
	logger.Infof("finishing oauth2 flow for provider: %s", provider)

	// This shouldn't happen because the router should 404 first, but just in case
	cfg, ok := o.Authboss.Config.Modules.OAuth2Providers[provider]
	if !ok {
		return errors.Errorf("oauth2 provider %q not found", provider)
	}

	wantState, ok := authboss.GetSession(r, authboss.SessionOAuth2State)
	if !ok {
		return errors.New("oauth2 endpoint hit without session state")
	}

	// Verify we got the same state in the session as was passed to us in the
	// query parameter.
	state := r.FormValue(FormValueOAuth2State)
	if state != wantState {
		return errOAuthStateValidation
	}

	rawParams, ok := authboss.GetSession(r, authboss.SessionOAuth2Params)
	var params map[string]string
	if ok {
		if err := json.Unmarshal([]byte(rawParams), &params); err != nil {
			return errors.Wrap(err, "failed to decode oauth2 params")
		}
	}

	authboss.DelSession(w, authboss.SessionOAuth2State)
	authboss.DelSession(w, authboss.SessionOAuth2Params)

	hasErr := r.FormValue("error")
	if len(hasErr) > 0 {
		reason := r.FormValue("error_reason")
		logger.Infof("oauth2 login failed: %s, reason: %s", hasErr, reason)

		handled, err := o.Authboss.Events.FireAfter(authboss.EventOAuth2Fail, w, r)
		if err != nil {
			return err
		} else if handled {
			return nil
		}

		ro := authboss.RedirectOptions{
			Code:         http.StatusTemporaryRedirect,
			RedirectPath: o.Authboss.Config.Paths.OAuth2LoginNotOK,
			Failure:      o.Localizef(r.Context(), authboss.TxtOAuth2LoginNotOK, provider),
		}
		return o.Authboss.Core.Redirector.Redirect(w, r, ro)
	}

	// Get the code which we can use to make an access token
	code := r.FormValue("code")
	token, err := exchanger(cfg.OAuth2Config, r.Context(), code)
	if err != nil {
		return errors.Wrap(err, "could not validate oauth2 code")
	}

	details, err := cfg.FindUserDetails(r.Context(), *cfg.OAuth2Config, token)
	if err != nil {
		return err
	}

	storer := authboss.EnsureCanOAuth2(o.Authboss.Config.Storage.Server)
	user, err := storer.NewFromOAuth2(r.Context(), provider, details)
	if err != nil {
		return errors.Wrap(err, "failed to create oauth2 user from values")
	}

	user.PutOAuth2Provider(provider)
	user.PutOAuth2AccessToken(token.AccessToken)
	user.PutOAuth2Expiry(token.Expiry)
	if len(token.RefreshToken) != 0 {
		user.PutOAuth2RefreshToken(token.RefreshToken)
	}

	if err := storer.SaveOAuth2(r.Context(), user); err != nil {
		return err
	}

	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))

	handled, err := o.Authboss.Events.FireBefore(authboss.EventOAuth2, w, r)
	if err != nil {
		return err
	} else if handled {
		return nil
	}

	// Fully log user in
	authboss.PutSession(w, authboss.SessionKey, authboss.MakeOAuth2PID(provider, user.GetOAuth2UID()))
	authboss.DelSession(w, authboss.SessionHalfAuthKey)

	// Create a query string from all the pieces we've received
	// as passthru from the original request.
	redirect := o.Authboss.Config.Paths.OAuth2LoginOK
	query := make(url.Values)
	for k, v := range params {
		switch k {
		case authboss.CookieRemember:
			if v == "true" {
				r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyValues, RMTrue{}))
			}
		case FormValueOAuth2Redir:
			redirect = v
		default:
			query.Set(k, v)
		}
	}

	handled, err = o.Authboss.Events.FireAfter(authboss.EventOAuth2, w, r)
	if err != nil {
		return err
	} else if handled {
		return nil
	}

	if len(query) > 0 {
		redirect = fmt.Sprintf("%s?%s", redirect, query.Encode())
	}

	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: redirect,
		Success:      o.Localizef(r.Context(), authboss.TxtOAuth2LoginOK, provider),
	}
	return o.Authboss.Config.Core.Redirector.Redirect(w, r, ro)
}

// RMTrue is a dummy struct implementing authboss.RememberValuer
// in order to tell the remember me module to remember them.
type RMTrue struct{}

// GetShouldRemember always returns true
func (RMTrue) GetShouldRemember() bool { return true }
