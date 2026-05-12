package authboss

import (
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Config holds all the configuration for both authboss and it's modules.
type Config struct {
	Paths struct {
		// Mount is the path to mount authboss's routes at (eg /auth).
		Mount string

		// NotAuthorized is the default URL to kick users back to when
		// they attempt an action that requires them to be logged in and
		// they're not auth'd
		NotAuthorized string

		// AuthLoginOK is the redirect path after a successful authentication.
		AuthLoginOK string

		// ConfirmOK once a user has confirmed their account
		// this says where they should go
		ConfirmOK string
		// ConfirmNotOK is used by the middleware, when a user is still supposed
		// to confirm their account, this is where they should be redirected to.
		ConfirmNotOK string

		// LockNotOK is a path to go to when the user fails
		LockNotOK string

		// LogoutOK is the redirect path after a log out.
		LogoutOK string

		// OAuth2LoginOK is the redirect path after a successful oauth2 login
		OAuth2LoginOK string
		// OAuth2LoginNotOK is the redirect path after
		// an unsuccessful oauth2 login
		OAuth2LoginNotOK string

		// RecoverOK is the redirect path after a successful recovery of a
		// password.
		RecoverOK string

		// RegisterOK is the redirect path after a successful registration.
		RegisterOK string

		// RootURL is the scheme+host+port of the web application
		// (eg https://www.happiness.com:8080) for url generation.
		// No trailing slash.
		RootURL string

		// TwoFactorEmailAuthNotOK is where a user is redirected when
		// the user attempts to add 2fa to their account without verifying
		// their e-mail OR when they've completed the first step towards
		// verification and need to check their e-mail to proceed.
		TwoFactorEmailAuthNotOK string
	}

	Modules struct {
		// BCryptCost is the cost of the bcrypt password hashing function.
		// Deprecated: Use Hasher instead.
		BCryptCost int

		// ConfirmMethod IS DEPRECATED! See MailRouteMethod instead.
		//
		// ConfirmMethod controls which http method confirm expects.
		// This is because typically this is a GET request since it's a link
		// from an e-mail, but in api-like cases it needs to be able to be a
		// post since there's data that must be sent to it.
		ConfirmMethod string

		// ExpireAfter controls the time an account is idle before being
		// logged out by the ExpireMiddleware.
		ExpireAfter time.Duration

		// LockAfter this many tries.
		LockAfter int
		// LockWindow is the waiting time before the number of attempts are reset.
		LockWindow time.Duration
		// LockDuration is how long an account is locked for.
		LockDuration time.Duration

		// IPLockAfter is the number of failed authentication attempts from a
		// single client IP before the IP is blocked. Zero falls back to the
		// iplock package default.
		IPLockAfter int
		// IPLockWindow is the rolling window in which IPLockAfter failed
		// attempts must occur to trigger a block. Zero falls back to the
		// iplock package default.
		IPLockWindow time.Duration
		// IPLockDuration is how long a client IP stays blocked once the
		// threshold is reached. Zero falls back to the iplock package default.
		IPLockDuration time.Duration

		// LogoutMethod is the method the logout route should use
		// (default should be DELETE)
		LogoutMethod string

		// MailRouteMethod is used to set the type of request that's used for
		// routes that require a token from an e-mail link's query string.
		// This is things like confirm and two factor e-mail auth.
		//
		// You should probably set this to POST if you are building an API
		// so that the user goes to the frontend with their link & token
		// and the front-end calls the API with the token in a POST JSON body.
		//
		// This configuration setting deprecates ConfirmMethod.
		// If ConfirmMethod is set to the default value (GET) then
		// MailRouteMethod is used. If ConfirmMethod is not the default value
		// then it is used until Authboss v3 when only MailRouteMethod will be
		// used.
		MailRouteMethod string

		// MailNoGoroutine is used to prevent the mailer from being launched
		// in a goroutine by the Authboss modules.
		//
		// This behavior will become the default in Authboss v3 and each
		// Mailer implementation will be required to use goroutines if it sees
		// fit.
		//
		// It's important that this is the case if you are using contexts
		// as the http request context will be cancelled by the Go http server
		// and it may interrupt your use of the context that the Authboss module
		// is passing to you, preventing proper use of it.
		MailNoGoroutine bool

		// RegisterPreserveFields are fields used with registration that are
		// to be rendered when post fails in a normal way
		// (for example validation errors), they will be passed back in the
		// data of the response under the key DataPreserve which
		// will be a map[string]string.
		//
		// All fields that are to be preserved must be able to be returned by
		// the ArbitraryValuer.GetValues()
		//
		// This means in order to have a field named "address" you would need
		// to have that returned by the ArbitraryValuer.GetValues() method and
		// then it would be available to be whitelisted by this
		// configuration variable.
		RegisterPreserveFields []string

		// RecoverTokenDuration controls how long a token sent via
		// email for password recovery is valid for.
		RecoverTokenDuration time.Duration
		// RecoverLoginAfterRecovery if true will log users in after password
		// recovery, if false they will be redirected and need to log in
		// again manually.
		RecoverLoginAfterRecovery bool

		// OAuth2Providers lists all providers that can be used. See
		// OAuthProvider documentation for more details.
		OAuth2Providers map[string]OAuth2Provider

		// TwoFactorEmailAuthRequired forces users to first confirm they have
		// access to their e-mail with the current device by clicking a link
		// and confirming a token stored in the session.
		TwoFactorEmailAuthRequired bool

		// TOTP2FAIssuer is the issuer that appears in the url when scanning
		// a qr code for google authenticator.
		TOTP2FAIssuer string

		// DEPRECATED: See ResponseOnUnauthed
		// RoutesRedirectOnUnauthed controls whether or not a user is redirected
		// or given a 404 when they are unauthenticated and attempting to access
		// a route that's login-protected inside Authboss itself.
		// The otp/twofactor modules all use authboss.Middleware to protect
		// their routes and this is the redirectToLogin parameter in that
		// middleware that they pass through.
		RoutesRedirectOnUnauthed bool

		// ResponseOnUnauthed controls how a user is responded to when
		// attempting to access a route that's login-protected inside Authboss
		// itself. The otp/twofactor modules all use authboss.Middleware2 to
		// protect their routes and this is the failResponse parameter in that
		// middleware that they pass through.
		//
		// This deprecates RoutesRedirectOnUnauthed. If RoutesRedirectOnUnauthed
		// is true, the value of this will be set to RespondRedirect until
		// authboss v3.
		ResponseOnUnauthed MWRespondOnFailure
	}

	Mail struct {
		// RootURL is a full path to an application that is hosting a front-end
		// Typically using a combination of Paths.RootURL and Paths.Mount
		// MailRoot will be assembled if not set.
		// Typically looks like: https://our-front-end.com/authenication
		// No trailing slash.
		RootURL string

		// From is the email address authboss e-mails come from.
		From string
		// FromName is the name authboss e-mails come from.
		FromName string
		// SubjectPrefix is used to add something to the front of the authboss
		// email subjects.
		SubjectPrefix string
	}

	Storage struct {
		// Storer is the interface through which Authboss accesses the web apps
		// database for user operations.
		Server ServerStorer

		// CookieState must be defined to provide an interface capapable of
		// storing cookies for the given response, and reading them from the
		// request.
		CookieState ClientStateReadWriter
		// SessionState must be defined to provide an interface capable of
		// storing session-only values for the given response, and reading them
		// from the request.
		SessionState ClientStateReadWriter

		// SessionStateWhitelistKeys are set to preserve keys in the session
		// when authboss.DelAllSession is called. A correct implementation
		// of ClientStateReadWriter will delete ALL session key-value pairs
		// unless that key is whitelisted here.
		SessionStateWhitelistKeys []string
	}

	Core struct {
		// Router is the entity that controls all routing to authboss routes
		// modules will register their routes with it.
		Router Router

		// ErrorHandler wraps http requests with centralized error handling.
		ErrorHandler ErrorHandler

		// Responder takes a generic response from a controller and prepares
		// the response, uses a renderer to create the body, and replies to the
		// http request.
		Responder HTTPResponder

		// Redirector can redirect a response, similar to Responder but
		// responsible only for redirection.
		Redirector HTTPRedirector

		// BodyReader reads validatable data from the body of a request to
		// be able to get data from the user's client.
		BodyReader BodyReader

		// ViewRenderer loads the templates for the application.
		ViewRenderer Renderer
		// MailRenderer loads the templates for mail. If this is nil, it will
		// fall back to using the Renderer created from the ViewLoader instead.
		MailRenderer Renderer

		// Mailer is the mailer being used to send e-mails out via smtp
		Mailer Mailer

		// Hasher hashes passwords into hashes
		Hasher Hasher

		// OneTimeTokenGenerator generates credentials (selector+verified+token)
		OneTimeTokenGenerator OneTimeTokenGenerator

		// Logger implies just a few log levels for use, can optionally
		// also implement the ContextLogger to be able to upgrade to a
		// request specific logger.
		Logger Logger

		// Localizer is used to translate strings into different languages.
		Localizer Localizer
	}
}

// Defaults sets the configuration's default values.
func (c *Config) Defaults() {
	c.Paths.Mount = "/auth"
	c.Paths.NotAuthorized = "/"
	c.Paths.AuthLoginOK = "/"
	c.Paths.ConfirmOK = "/"
	c.Paths.ConfirmNotOK = "/"
	c.Paths.LockNotOK = "/"
	c.Paths.LogoutOK = "/"
	c.Paths.OAuth2LoginOK = "/"
	c.Paths.OAuth2LoginNotOK = "/"
	c.Paths.RecoverOK = "/"
	c.Paths.RegisterOK = "/"
	c.Paths.RootURL = "http://localhost:8080"
	c.Paths.TwoFactorEmailAuthNotOK = "/"

	c.Modules.BCryptCost = bcrypt.DefaultCost
	c.Modules.ConfirmMethod = http.MethodGet
	c.Modules.ExpireAfter = time.Hour
	c.Modules.LockAfter = 3
	c.Modules.LockWindow = 5 * time.Minute
	c.Modules.LockDuration = 12 * time.Hour
	c.Modules.LogoutMethod = "DELETE"
	c.Modules.MailRouteMethod = http.MethodGet
	c.Modules.RecoverLoginAfterRecovery = false
	c.Modules.RecoverTokenDuration = 24 * time.Hour

	c.Core.OneTimeTokenGenerator = NewSha512TokenGenerator()
}
