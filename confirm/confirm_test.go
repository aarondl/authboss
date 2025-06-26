package confirm

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aarondl/authboss/v3"
	"github.com/aarondl/authboss/v3/mocks"
)

func TestInit(t *testing.T) {
	t.Parallel()

	ab := authboss.New()

	router := &mocks.Router{}
	renderer := &mocks.Renderer{}
	errHandler := &mocks.ErrorHandler{}
	ab.Config.Core.Router = router
	ab.Config.Core.MailRenderer = renderer
	ab.Config.Core.ErrorHandler = errHandler

	c := &Confirm{}
	if err := c.Init(ab); err != nil {
		t.Fatal(err)
	}

	if err := renderer.HasLoadedViews(EmailConfirmHTML, EmailConfirmTxt); err != nil {
		t.Error(err)
	}

	if err := router.HasGets("/confirm"); err != nil {
		t.Error(err)
	}
}

type testHarness struct {
	confirm *Confirm
	ab      *authboss.Authboss

	bodyReader *mocks.BodyReader
	mailer     *mocks.Emailer
	redirector *mocks.Redirector
	renderer   *mocks.Renderer
	responder  *mocks.Responder
	session    *mocks.ClientStateRW
	storer     *mocks.ServerStorer
}

func testSetup() *testHarness {
	harness := &testHarness{}

	harness.ab = authboss.New()
	harness.bodyReader = &mocks.BodyReader{}
	harness.mailer = &mocks.Emailer{}
	harness.redirector = &mocks.Redirector{}
	harness.renderer = &mocks.Renderer{}
	harness.responder = &mocks.Responder{}
	harness.session = mocks.NewClientRW()
	harness.storer = mocks.NewServerStorer()

	harness.ab.Paths.ConfirmOK = "/confirm/ok"
	harness.ab.Paths.ConfirmNotOK = "/confirm/not/ok"
	harness.ab.Modules.MailNoGoroutine = true

	harness.ab.Config.Core.BodyReader = harness.bodyReader
	harness.ab.Config.Core.Logger = mocks.Logger{}
	harness.ab.Config.Core.Hasher = mocks.Hasher{}
	harness.ab.Config.Core.Mailer = harness.mailer
	harness.ab.Config.Core.Redirector = harness.redirector
	harness.ab.Config.Core.MailRenderer = harness.renderer
	harness.ab.Config.Core.Responder = harness.responder
	harness.ab.Config.Storage.SessionState = harness.session
	harness.ab.Config.Storage.Server = harness.storer

	harness.confirm = &Confirm{harness.ab}

	return harness
}

func TestPreventAuthAllow(t *testing.T) {
	t.Parallel()

	harness := testSetup()

	user := &mocks.User{
		Confirmed: true,
	}

	r := mocks.Request("GET")
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
	w := httptest.NewRecorder()

	handled, err := harness.confirm.PreventAuth(w, r, false)
	if err != nil {
		t.Error(err)
	}

	if handled {
		t.Error("it should not have been handled")
	}
}

func TestPreventDisallow(t *testing.T) {
	t.Parallel()

	harness := testSetup()

	user := &mocks.User{
		Confirmed: false,
	}

	r := mocks.Request("GET")
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
	w := httptest.NewRecorder()

	handled, err := harness.confirm.PreventAuth(w, r, false)
	if err != nil {
		t.Error(err)
	}

	if !handled {
		t.Error("it should have been handled")
	}

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("redirect did not occur")
	}

	if p := harness.redirector.Options.RedirectPath; p != "/confirm/not/ok" {
		t.Error("redirect path was wrong:", p)
	}
}

func TestStartConfirmationWeb(t *testing.T) {
	t.Parallel()

	harness := testSetup()

	user := &mocks.User{Email: "test@test.com"}
	harness.storer.Users["test@test.com"] = user

	r := mocks.Request("GET")
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
	w := httptest.NewRecorder()

	handled, err := harness.confirm.StartConfirmationWeb(w, r, false)
	if err != nil {
		t.Error(err)
	}

	if !handled {
		t.Error("it should always be handled")
	}

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("redirect did not occur")
	}

	if p := harness.redirector.Options.RedirectPath; p != "/confirm/not/ok" {
		t.Error("redirect path was wrong:", p)
	}

	if to := harness.mailer.Email.To[0]; to != "test@test.com" {
		t.Error("mailer sent e-mail to wrong person:", to)
	}
}

func TestGetSuccess(t *testing.T) {
	t.Parallel()

	harness := testSetup()

	selector, verifier, token, err := harness.ab.Config.Core.OneTimeTokenGenerator.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}

	user := &mocks.User{Email: "test@test.com", Confirmed: false, ConfirmSelector: selector, ConfirmVerifier: verifier}
	harness.storer.Users["test@test.com"] = user
	harness.bodyReader.Return = mocks.Values{
		Token: token,
	}

	r := mocks.Request("GET")
	w := httptest.NewRecorder()

	if err := harness.confirm.Get(w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("expected a redirect, got:", w.Code)
	}
	if p := harness.redirector.Options.RedirectPath; p != harness.ab.Paths.ConfirmOK {
		t.Error("redir path was wrong:", p)
	}

	if len(user.ConfirmSelector) != 0 {
		t.Error("the confirm selector should have been erased")
	}
	if len(user.ConfirmVerifier) != 0 {
		t.Error("the confirm verifier should have been erased")
	}
	if !user.Confirmed {
		t.Error("the user should have been confirmed")
	}
}

func TestGetValidationFailure(t *testing.T) {
	t.Parallel()

	harness := testSetup()

	harness.bodyReader.Return = mocks.Values{
		Errors: []error{errors.New("fail")},
	}

	r := mocks.Request("GET")
	w := httptest.NewRecorder()

	if err := harness.confirm.Get(w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("expected a redirect, got:", w.Code)
	}
	if p := harness.redirector.Options.RedirectPath; p != harness.ab.Paths.ConfirmNotOK {
		t.Error("redir path was wrong:", p)
	}
	if reason := harness.redirector.Options.Failure; reason != harness.ab.Localizef(context.Background(), authboss.TxtInvalidConfirmToken) {
		t.Error("reason for failure was wrong:", reason)
	}
}

func TestGetBase64DecodeFailure(t *testing.T) {
	t.Parallel()

	harness := testSetup()

	harness.bodyReader.Return = mocks.Values{
		Token: "5",
	}

	r := mocks.Request("GET")
	w := httptest.NewRecorder()

	if err := harness.confirm.Get(w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("expected a redirect, got:", w.Code)
	}
	if p := harness.redirector.Options.RedirectPath; p != harness.ab.Paths.ConfirmNotOK {
		t.Error("redir path was wrong:", p)
	}
	if reason := harness.redirector.Options.Failure; reason != harness.ab.Localizef(context.Background(), authboss.TxtInvalidConfirmToken) {
		t.Error("reason for failure was wrong:", reason)
	}
}

func TestGetUserNotFoundFailure(t *testing.T) {
	t.Parallel()

	harness := testSetup()

	_, _, token, err := harness.ab.Config.Core.OneTimeTokenGenerator.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}

	harness.bodyReader.Return = mocks.Values{
		Token: token,
	}

	r := mocks.Request("GET")
	w := httptest.NewRecorder()

	if err := harness.confirm.Get(w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("expected a redirect, got:", w.Code)
	}
	if p := harness.redirector.Options.RedirectPath; p != harness.ab.Paths.ConfirmNotOK {
		t.Error("redir path was wrong:", p)
	}
	if reason := harness.redirector.Options.Failure; reason != harness.ab.Localizef(context.Background(), authboss.TxtInvalidConfirmToken) {
		t.Error("reason for failure was wrong:", reason)
	}
}

func TestMiddlewareAllow(t *testing.T) {
	t.Parallel()

	ab := authboss.New()
	called := false
	server := Middleware(ab)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	user := &mocks.User{
		Confirmed: true,
	}

	r := mocks.Request("GET")
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
	w := httptest.NewRecorder()

	server.ServeHTTP(w, r)

	if !called {
		t.Error("The user should have been allowed through")
	}
}

func TestMiddlewareDisallow(t *testing.T) {
	t.Parallel()

	ab := authboss.New()
	redirector := &mocks.Redirector{}
	ab.Config.Paths.ConfirmNotOK = "/confirm/not/ok"
	ab.Config.Core.Logger = mocks.Logger{}
	ab.Config.Core.Redirector = redirector

	called := false
	server := Middleware(ab)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	user := &mocks.User{
		Confirmed: false,
	}

	r := mocks.Request("GET")
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
	w := httptest.NewRecorder()

	server.ServeHTTP(w, r)

	if called {
		t.Error("The user should not have been allowed through")
	}
	if redirector.Options.Code != http.StatusTemporaryRedirect {
		t.Error("expected a redirect, but got:", redirector.Options.Code)
	}
	if p := redirector.Options.RedirectPath; p != "/confirm/not/ok" {
		t.Error("redirect path wrong:", p)
	}
}

func TestMailURL(t *testing.T) {
	t.Parallel()

	h := testSetup()
	h.ab.Config.Paths.RootURL = "https://api.test.com:6343"
	h.ab.Config.Paths.Mount = "/v1/auth"

	want := "https://api.test.com:6343/v1/auth/confirm?cnf=abc"
	if got := h.confirm.mailURL("abc"); got != want {
		t.Error("want:", want, "got:", got)
	}

	h.ab.Config.Mail.RootURL = "https://test.com:3333/testauth"

	want = "https://test.com:3333/testauth/confirm?cnf=abc"
	if got := h.confirm.mailURL("abc"); got != want {
		t.Error("want:", want, "got:", got)
	}
}

func TestGenerateRecoverCreds(t *testing.T) {
	t.Parallel()

	credsGenerator := authboss.NewSha512TokenGenerator()

	selector, verifier, token, err := credsGenerator.GenerateToken()
	if err != nil {
		t.Error(err)
	}

	if verifier == selector {
		t.Error("the verifier and selector should be different")
	}

	confirmTokenSplit := credsGenerator.TokenSize() / 2

	// base64 length: n = 64; 4*(64/3) = 85.3; round to nearest 4: 88
	if len(verifier) != 88 {
		t.Errorf("verifier length was wrong (%d): %s", len(verifier), verifier)
	}

	// base64 length: n = 64; 4*(64/3) = 85.3; round to nearest 4: 88
	if len(selector) != 88 {
		t.Errorf("selector length was wrong (%d): %s", len(selector), selector)
	}

	// base64 length: n = 64; 4*(64/3) = 85.33; round to nearest 4: 88
	if len(token) != 88 {
		t.Errorf("token length was wrong (%d): %s", len(token), token)
	}

	rawToken, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		t.Error(err)
	}

	rawSelector, err := base64.StdEncoding.DecodeString(selector)
	if err != nil {
		t.Error(err)
	}
	rawVerifier, err := base64.StdEncoding.DecodeString(verifier)
	if err != nil {
		t.Error(err)
	}

	checkSelector := sha512.Sum512(rawToken[:confirmTokenSplit])
	if 0 != bytes.Compare(checkSelector[:], rawSelector) {
		t.Error("expected selector to match")
	}
	checkVerifier := sha512.Sum512(rawToken[confirmTokenSplit:])
	if 0 != bytes.Compare(checkVerifier[:], rawVerifier) {
		t.Error("expected verifier to match")
	}
}
