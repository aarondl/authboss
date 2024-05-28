package authboss

import (
	"context"
	"net/url"

	"golang.org/x/oauth2"
)

/*
OAuth2Provider is the entire configuration
required to authenticate with this provider.

The OAuth2Config does not need a redirect URL because it will
be automatically created by the route registration in the oauth2 module.

AdditionalParams can be used to specify extra parameters to tack on to the
end of the initial request, this allows for provider specific oauth options
like access_type=offline to be passed to the provider.

FindUserDetails gives the config and the token allowing an http client using the
authenticated token to be created, a call is then made to a known endpoint that will
return details about the user we've retrieved the token for. Those details are returned
as a map[string]string and subsequently passed into OAuth2ServerStorer.NewFromOAuth2.
API this must be handled for each provider separately.
*/
type OAuth2Provider struct {
	OAuth2Config          *oauth2.Config
	WhitelistRedirectURIs []string
	AdditionalParams      url.Values
	FindUserDetails       func(context.Context, oauth2.Config, *oauth2.Token) (map[string]string, error)
}
