package oauth2

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/friendsofgo/errors"
	"golang.org/x/oauth2"
)

// Constants for returning in the FindUserDetails call
const (
	OAuth2UID   = "uid"
	OAuth2Email = "email"
	OAuth2Name  = "name"
)

const (
	googleInfoEndpoint   = `https://www.googleapis.com/userinfo/v2/me`
	facebookInfoEndpoint = `https://graph.facebook.com/me?fields=name,email`
	githubInfoEndpoint   = `https://api.github.com/user`
)

type googleMeResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// testing
var clientGet = (*http.Client).Get

// GoogleUserDetails can be used as a FindUserDetails function
// for an authboss.OAuth2Provider
func GoogleUserDetails(ctx context.Context, cfg oauth2.Config, token *oauth2.Token) (map[string]string, error) {
	client := cfg.Client(ctx, token)
	resp, err := clientGet(client, googleInfoEndpoint)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	byt, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read body from google oauth2 endpoint")
	}

	var response googleMeResponse
	if err = json.Unmarshal(byt, &response); err != nil {
		return nil, err
	}

	return map[string]string{
		OAuth2UID:   response.ID,
		OAuth2Email: response.Email,
	}, nil
}

type facebookMeResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// FacebookUserDetails can be used as a FindUserDetails function
// for an authboss.OAuth2Provider
func FacebookUserDetails(ctx context.Context, cfg oauth2.Config, token *oauth2.Token) (map[string]string, error) {
	client := cfg.Client(ctx, token)
	resp, err := clientGet(client, facebookInfoEndpoint)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	byt, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read body from facebook oauth2 endpoint")
	}

	var response facebookMeResponse
	if err = json.Unmarshal(byt, &response); err != nil {
		return nil, errors.Wrap(err, "failed to parse json from facebook oauth2 endpoint")
	}

	return map[string]string{
		OAuth2UID:   response.ID,
		OAuth2Email: response.Email,
		OAuth2Name:  response.Name,
	}, nil
}

type githubMeResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// GithubUserDetails can be used as a FindUserDetails function
// for an authboss.OAuth2Provider
func GithubUserDetails(ctx context.Context, cfg oauth2.Config, token *oauth2.Token) (map[string]string, error) {
	client := cfg.Client(ctx, token)
	resp, err := clientGet(client, githubInfoEndpoint)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	byt, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read body from github oauth2 endpoint")
	}

	var response githubMeResponse
	if err = json.Unmarshal(byt, &response); err != nil {
		return nil, errors.Wrap(err, "failed to parse json from github oauth2 endpoint")
	}

	return map[string]string{
		OAuth2UID:   response.ID,
		OAuth2Email: response.Email,
		OAuth2Name:  response.Name,
	}, nil

}
