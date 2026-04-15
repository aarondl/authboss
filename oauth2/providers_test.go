package oauth2

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func init() {
	// This has an extra parameter that the Google client wouldn't normally
	// get, but it'll safely be ignored.
	clientGet = func(_ *http.Client, url string) (*http.Response, error) {
		return &http.Response{
			Body: io.NopCloser(strings.NewReader(`{"id":"id", "email":"email", "name": "name"}`)),
		}, nil
	}
}

func TestGoogle(t *testing.T) {
	t.Parallel()

	cfg := *testProviders["google"].OAuth2Config
	tok := &oauth2.Token{
		AccessToken:  "token",
		TokenType:    "Bearer",
		RefreshToken: "refresh",
		Expiry:       time.Now().Add(60 * time.Minute),
	}

	details, err := GoogleUserDetails(context.Background(), cfg, tok)
	if err != nil {
		t.Error(err)
	}

	if uid, ok := details[OAuth2UID]; !ok || uid != "id" {
		t.Error("UID wrong:", uid)
	}
	if email, ok := details[OAuth2Email]; !ok || email != "email" {
		t.Error("Email wrong:", email)
	}
}

func TestFacebook(t *testing.T) {
	t.Parallel()

	cfg := *testProviders["facebook"].OAuth2Config
	tok := &oauth2.Token{
		AccessToken:  "token",
		TokenType:    "Bearer",
		RefreshToken: "refresh",
		Expiry:       time.Now().Add(60 * time.Minute),
	}

	details, err := FacebookUserDetails(context.Background(), cfg, tok)
	if err != nil {
		t.Error(err)
	}

	if uid, ok := details[OAuth2UID]; !ok || uid != "id" {
		t.Error("UID wrong:", uid)
	}
	if email, ok := details[OAuth2Email]; !ok || email != "email" {
		t.Error("Email wrong:", email)
	}
	if name, ok := details[OAuth2Name]; !ok || name != "name" {
		t.Error("Name wrong:", name)
	}
}

func TestGithub(t *testing.T) {

	t.Parallel()

	cfg := *testProviders["github"].OAuth2Config

	tok := &oauth2.Token{

		AccessToken:  "token",
		TokenType:    "Bearer",
		RefreshToken: "refresh",
		Expiry:       time.Now().Add(60 * time.Minute),
	}

	details, err := GithubUserDetails(context.Background(), cfg, tok)

	if err != nil {

		t.Error(err)
	}

	if uid, ok := details[OAuth2UID]; !ok || uid != "id" {
		t.Error("UID wrong:", uid)
	}
	if email, ok := details[OAuth2Email]; !ok || email != "email" {
		t.Error("Email wrong:", email)
	}
	if name, ok := details[OAuth2Name]; !ok || name != "name" {
		t.Error("Name wrong:", name)
	}

}
