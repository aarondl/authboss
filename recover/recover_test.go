package recover

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aarondl/authboss/v3"
	"github.com/aarondl/authboss/v3/mocks"
)

const (
	testSelector = `rnaGE8TDilrINHPxq/2xNU1FUTzsUSX8FvN5YzooyyWKk88fw1DjjbKBRGFtGew9OeZ+xeCC4mslfvQQMYspIg==`
	testVerifier = `W1Mz30QhavVM4d8jKaFtxGBfb4GX+fOn7V0Pc1WeftgtyOtY5OX7sY9gIeY5CIY4n8LvfWy14W7/6rs2KO9pgA==`
	testToken    = `w5OZ51E61Q6wsJOVr9o7KmyepP7Od5VBHQ1ADDUBkiGGMjKfnMFPjtvNpLjLKJqffw72KWZzNLj0Cs8wqywdEQ==`
)

func TestInit(t *testing.T) {
	t.Parallel()

	ab := authboss.New()

	router := &mocks.Router{}
	renderer := &mocks.Renderer{}
	mailRenderer := &mocks.Renderer{}
	errHandler := &mocks.ErrorHandler{}
	ab.Config.Core.Router = router
	ab.Config.Core.ViewRenderer = renderer
	ab.Config.Core.MailRenderer = mailRenderer
	ab.Config.Core.ErrorHandler = errHandler

	r := &Recover{}
	if err := r.Init(ab); err != nil {
		t.Fatal(err)
	}

	if err := renderer.HasLoadedViews(PageRecoverStart, PageRecoverEnd); err != nil {
		t.Error(err)
	}
	if err := mailRenderer.HasLoadedViews(EmailRecoverHTML, EmailRecoverTxt); err != nil {
		t.Error(err)
	}

	if err := router.HasGets("/recover", "/recover/end"); err != nil {
		t.Error(err)
	}
	if err := router.HasPosts("/recover", "/recover/end"); err != nil {
		t.Error(err)
	}
}

type testHarness struct {
	recover *Recover
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

	harness.ab.Paths.RecoverOK = "/recover/ok"
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

	harness.recover = &Recover{harness.ab}

	return harness
}

func TestStartGet(t *testing.T) {
	t.Parallel()

	h := testSetup()

	r := mocks.Request("GET")
	w := httptest.NewRecorder()

	if err := h.recover.StartGet(w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusOK {
		t.Error("code was wrong:", w.Code)
	}
	if h.responder.Page != PageRecoverStart {
		t.Error("page was wrong:", h.responder.Page)
	}
	if h.responder.Data != nil {
		t.Error("expected no data:", h.responder.Data)
	}
}

func TestStartPostSuccess(t *testing.T) {
	t.Parallel()

	h := testSetup()

	h.bodyReader.Return = &mocks.Values{
		PID: "test@test.com",
	}
	h.storer.Users["test@test.com"] = &mocks.User{
		Email:    "test@test.com",
		Password: "i can't recall, doesn't seem like something bcrypted though",
	}

	r := mocks.Request("GET")
	w := httptest.NewRecorder()

	if err := h.recover.StartPost(w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("code was wrong:", w.Code)
	}
	if h.redirector.Options.RedirectPath != h.ab.Config.Paths.RecoverOK {
		t.Error("page was wrong:", h.responder.Page)
	}
	if len(h.redirector.Options.Success) == 0 {
		t.Error("expected a nice success message")
	}

	if h.mailer.Email.To[0] != "test@test.com" {
		t.Error("e-mail to address is wrong:", h.mailer.Email.To)
	}
	if !strings.HasSuffix(h.mailer.Email.Subject, "Password Reset") {
		t.Error("e-mail subject line is wrong:", h.mailer.Email.Subject)
	}
	if len(h.renderer.Data[DataRecoverURL].(string)) == 0 {
		t.Errorf("the renderer's url in data was missing: %#v", h.renderer.Data)
	}
}

func TestStartPostFailure(t *testing.T) {
	t.Parallel()

	h := testSetup()

	h.bodyReader.Return = &mocks.Values{
		PID: "test@test.com",
	}

	r := mocks.Request("GET")
	w := httptest.NewRecorder()

	if err := h.recover.StartPost(w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("code was wrong:", w.Code)
	}
	if h.redirector.Options.RedirectPath != h.ab.Config.Paths.RecoverOK {
		t.Error("page was wrong:", h.responder.Page)
	}
	if len(h.redirector.Options.Success) == 0 {
		t.Error("expected a nice success message")
	}

	if len(h.mailer.Email.To) != 0 {
		t.Error("should not have sent an e-mail out!")
	}
}

func TestEndGet(t *testing.T) {
	t.Parallel()

	h := testSetup()

	h.bodyReader.Return = &mocks.Values{
		Token: "abcd",
	}

	r := mocks.Request("GET")
	w := httptest.NewRecorder()

	if err := h.recover.EndGet(w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusOK {
		t.Error("code was wrong:", w.Code)
	}
	if h.responder.Page != PageRecoverEnd {
		t.Error("page was wrong:", h.responder.Page)
	}
	if h.responder.Data[DataRecoverToken].(string) != "abcd" {
		t.Errorf("recovery token is wrong: %#v", h.responder.Data)
	}
}

func TestEndPostSuccess(t *testing.T) {
	t.Parallel()

	h := testSetup()

	h.bodyReader.Return = &mocks.Values{
		Token: testToken,
	}
	h.storer.Users["test@test.com"] = &mocks.User{
		Email:              "test@test.com",
		Password:           "to-overwrite",
		RecoverSelector:    testSelector,
		RecoverVerifier:    testVerifier,
		RecoverTokenExpiry: time.Now().UTC().AddDate(0, 0, 1),
	}

	r := mocks.Request("POST")
	w := httptest.NewRecorder()

	if err := h.recover.EndPost(w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("code was wrong:", w.Code)
	}
	if p := h.redirector.Options.RedirectPath; p != h.ab.Paths.RecoverOK {
		t.Error("path was wrong:", p)
	}
	if len(h.session.ClientValues[authboss.SessionKey]) != 0 {
		t.Error("should not have logged in the user")
	}
	if !strings.Contains(h.redirector.Options.Success, "updated password") {
		t.Error("should talk about recovering the password")
	}
	if strings.Contains(h.redirector.Options.Success, "logged in") {
		t.Error("should not talk about logging in")
	}
}

func TestEndPostSuccessLogin(t *testing.T) {
	t.Parallel()

	h := testSetup()

	h.ab.Config.Modules.RecoverLoginAfterRecovery = true
	h.bodyReader.Return = &mocks.Values{
		Token: testToken,
	}
	h.storer.Users["test@test.com"] = &mocks.User{
		Email:              "test@test.com",
		Password:           "to-overwrite",
		RecoverSelector:    testSelector,
		RecoverVerifier:    testVerifier,
		RecoverTokenExpiry: time.Now().UTC().AddDate(0, 0, 1),
	}

	callbacks := 0
	h.ab.Events.After(authboss.EventRecoverEnd, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
		if callbacks != 0 {
			t.Error("after recover end was not called 1st")
		}
		callbacks += 1
		return false, nil
	})
	h.ab.Events.Before(authboss.EventAuth, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
		if callbacks != 1 {
			t.Error("before auth was not called 2nd")
		}
		callbacks += 1
		return false, nil
	})
	h.ab.Events.Before(authboss.EventAuthHijack, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
		if callbacks != 2 {
			t.Error("before auth hijack was not called 3rd")
		}
		callbacks += 1
		return false, nil
	})
	h.ab.Events.After(authboss.EventAuth, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
		if callbacks != 3 {
			t.Error("after auth was not called 4th")
		}
		callbacks += 1
		return false, nil
	})

	r := mocks.Request("POST")
	w := httptest.NewRecorder()

	if err := h.recover.EndPost(h.ab.NewResponse(w), r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("code was wrong:", w.Code)
	}
	if p := h.redirector.Options.RedirectPath; p != h.ab.Paths.RecoverOK {
		t.Error("path was wrong:", p)
	}
	if len(h.session.ClientValues[authboss.SessionKey]) == 0 {
		t.Error("it should have logged in the user")
	}
	if !strings.Contains(h.redirector.Options.Success, "logged in") {
		t.Error("should talk about logging in")
	}
	if callbacks != 4 {
		t.Error("all 4 callbacks were not called")
	}
}

func TestEndPostValidationFailure(t *testing.T) {
	t.Parallel()

	h := testSetup()

	h.bodyReader.Return = &mocks.Values{
		Errors: []error{errors.New("password is not sufficiently complex")},
	}
	h.storer.Users["test@test.com"] = &mocks.User{
		Email:              "test@test.com",
		Password:           "to-overwrite",
		RecoverSelector:    testSelector,
		RecoverVerifier:    testVerifier,
		RecoverTokenExpiry: time.Now().UTC().AddDate(0, 0, 1),
	}

	r := mocks.Request("POST")
	w := httptest.NewRecorder()

	if err := h.recover.EndPost(w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusOK {
		t.Error("code was wrong:", w.Code)
	}
	if h.responder.Page != PageRecoverEnd {
		t.Error("rendered the wrong page")
	}
	if m, ok := h.responder.Data[authboss.DataValidation].(map[string][]string); !ok {
		t.Error("expected validation errors")
	} else if m[""][0] != "password is not sufficiently complex" {
		t.Error("error message data was not correct:", m[""])
	}
	if len(h.session.ClientValues[authboss.SessionKey]) != 0 {
		t.Error("should not have logged in the user")
	}
}

func TestEndPostInvalidBase64(t *testing.T) {
	t.Parallel()

	h := testSetup()

	h.bodyReader.Return = &mocks.Values{
		Token: "a",
	}

	r := mocks.Request("GET")
	w := httptest.NewRecorder()

	if err := h.recover.EndPost(w, r); err != nil {
		t.Error(err)
	}

	invalidCheck(t, h, w)
}

func TestEndPostExpiredToken(t *testing.T) {
	t.Parallel()

	h := testSetup()

	h.bodyReader.Return = &mocks.Values{
		Token: testToken,
	}
	h.storer.Users["test@test.com"] = &mocks.User{
		Email:              "test@test.com",
		Password:           "to-overwrite",
		RecoverSelector:    testSelector,
		RecoverVerifier:    testVerifier,
		RecoverTokenExpiry: time.Now().UTC().AddDate(0, 0, -1),
	}

	r := mocks.Request("GET")
	w := httptest.NewRecorder()

	if err := h.recover.EndPost(w, r); err != nil {
		t.Error(err)
	}

	invalidCheck(t, h, w)
}

func TestEndPostUserNotExist(t *testing.T) {
	t.Parallel()

	h := testSetup()

	h.bodyReader.Return = &mocks.Values{
		Token: testToken,
	}

	r := mocks.Request("GET")
	w := httptest.NewRecorder()

	if err := h.recover.EndPost(w, r); err != nil {
		t.Error(err)
	}

	invalidCheck(t, h, w)
}

func TestMailURL(t *testing.T) {
	t.Parallel()

	h := testSetup()
	h.ab.Config.Paths.RootURL = "https://api.test.com:6343"
	h.ab.Config.Paths.Mount = "/v1/auth"

	want := "https://api.test.com:6343/v1/auth/recover/end?token=abc"
	if got := h.recover.mailURL("abc"); got != want {
		t.Error("want:", want, "got:", got)
	}

	h.ab.Config.Mail.RootURL = "https://test.com:3333/testauth"

	want = "https://test.com:3333/testauth/recover/end?token=abc"
	if got := h.recover.mailURL("abc"); got != want {
		t.Error("want:", want, "got:", got)
	}
}

func invalidCheck(t *testing.T, h *testHarness, w *httptest.ResponseRecorder) {
	t.Helper()

	if w.Code != http.StatusOK {
		t.Error("code was wrong:", w.Code)
	}
	if h.responder.Page != PageRecoverEnd {
		t.Error("page was wrong:", h.responder.Page)
	}
	if h.responder.Data[authboss.DataValidation].(map[string][]string)[""][0] != "recovery token is invalid" {
		t.Error("expected a vague error to mislead")
	}
}

func TestGenerateRecoverCreds(t *testing.T) {
	t.Parallel()

	credsGenerator := authboss.NewSha512TokenGenerator()

	selector, verifier, token, err := credsGenerator.GenerateToken()
	if err != nil {
		t.Error(err)
	}
	recoverTokenSplit := credsGenerator.TokenSize() / 2

	if verifier == selector {
		t.Error("the verifier and selector should be different")
	}

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

	checkSelector := sha512.Sum512(rawToken[:recoverTokenSplit])
	if 0 != bytes.Compare(checkSelector[:], rawSelector) {
		t.Error("expected selector to match")
	}
	checkVerifier := sha512.Sum512(rawToken[recoverTokenSplit:])
	if 0 != bytes.Compare(checkVerifier[:], rawVerifier) {
		t.Error("expected verifier to match")
	}
}
