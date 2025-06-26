package twofactor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/aarondl/authboss/v3"
	"github.com/aarondl/authboss/v3/mocks"
)

func TestSetupEmailVerify(t *testing.T) {
	t.Parallel()

	router := &mocks.Router{}
	renderer := &mocks.Renderer{}
	mailRenderer := &mocks.Renderer{}

	ab := &authboss.Authboss{}
	ab.Config.Core.Router = router
	ab.Config.Core.ViewRenderer = renderer
	ab.Config.Core.MailRenderer = mailRenderer
	ab.Config.Core.ErrorHandler = &mocks.ErrorHandler{}

	ab.Config.Modules.MailRouteMethod = http.MethodGet

	if _, err := SetupEmailVerify(ab, "totp", "/2fa/totp/setup"); err != nil {
		t.Error(err)
	}

	if err := router.HasGets("/2fa/totp/email/verify", "/2fa/totp/email/verify/end"); err != nil {
		t.Error(err)
	}
	if err := router.HasPosts("/2fa/totp/email/verify"); err != nil {
		t.Error(err)
	}

	if err := renderer.HasLoadedViews(PageVerify2FA); err != nil {
		t.Error(err)
	}

	if err := mailRenderer.HasLoadedViews(EmailVerifyHTML, EmailVerifyTxt); err != nil {
		t.Error(err)
	}
}

type testEmailVerifyHarness struct {
	emailverify EmailVerify
	ab          *authboss.Authboss

	bodyReader *mocks.BodyReader
	mailer     *mocks.Emailer
	responder  *mocks.Responder
	renderer   *mocks.Renderer
	redirector *mocks.Redirector
	session    *mocks.ClientStateRW
	storer     *mocks.ServerStorer
}

func testEmailVerifySetup() *testEmailVerifyHarness {
	harness := &testEmailVerifyHarness{}

	harness.ab = authboss.New()
	harness.bodyReader = &mocks.BodyReader{}
	harness.mailer = &mocks.Emailer{}
	harness.redirector = &mocks.Redirector{}
	harness.renderer = &mocks.Renderer{}
	harness.responder = &mocks.Responder{}
	harness.session = mocks.NewClientRW()
	harness.storer = mocks.NewServerStorer()

	harness.ab.Config.Core.BodyReader = harness.bodyReader
	harness.ab.Config.Core.Logger = mocks.Logger{}
	harness.ab.Config.Core.Responder = harness.responder
	harness.ab.Config.Core.Redirector = harness.redirector
	harness.ab.Config.Core.Mailer = harness.mailer
	harness.ab.Config.Core.MailRenderer = harness.renderer
	harness.ab.Config.Storage.SessionState = harness.session
	harness.ab.Config.Storage.Server = harness.storer

	harness.ab.Config.Modules.TwoFactorEmailAuthRequired = true
	harness.ab.Config.Modules.MailNoGoroutine = true

	harness.emailverify = EmailVerify{
		Authboss:          harness.ab,
		TwofactorKind:     "totp",
		TwofactorSetupURL: "/2fa/totp/setup",
	}

	return harness
}

func (h *testEmailVerifyHarness) loadClientState(w http.ResponseWriter, r **http.Request) {
	req, err := h.ab.LoadClientState(w, *r)
	if err != nil {
		panic(err)
	}

	*r = req
}

func (h *testEmailVerifyHarness) putUserInCtx(u *mocks.User, r **http.Request) {
	req := (*r).WithContext(context.WithValue((*r).Context(), authboss.CTXKeyUser, u))
	*r = req
}

func TestEmailVerifyGetStart(t *testing.T) {
	t.Parallel()

	h := testEmailVerifySetup()

	rec := httptest.NewRecorder()
	r := mocks.Request("GET")
	w := h.ab.NewResponse(rec)

	u := &mocks.User{Email: "test@test.com"}
	h.putUserInCtx(u, &r)
	h.loadClientState(w, &r)

	if err := h.emailverify.GetStart(w, r); err != nil {
		t.Fatal(err)
	}

	if got := h.responder.Data["email"]; got != "test@test.com" {
		t.Error("email was wrong:", got)
	}

	if got := h.responder.Page; got != PageVerify2FA {
		t.Error("page was wrong:", got)
	}
}

func TestEmailVerifyPostStart(t *testing.T) {
	t.Parallel()
	h := testEmailVerifySetup()

	rec := httptest.NewRecorder()
	r := mocks.Request("POST")
	w := h.ab.NewResponse(rec)

	u := &mocks.User{Email: "test@test.com"}
	h.putUserInCtx(u, &r)
	h.loadClientState(w, &r)

	if err := h.emailverify.PostStart(w, r); err != nil {
		t.Fatal(err)
	}

	ro := h.redirector.Options
	if ro.Code != http.StatusTemporaryRedirect {
		t.Error("code wrong:", ro.Code)
	}

	if ro.Success != h.ab.Localizef(context.Background(), authboss.TxtEmailVerifyTriggered) {
		t.Error("message was wrong:", ro.Success)
	}

	mail := h.mailer.Email
	if mail.To[0] != "test@test.com" {
		t.Error("email was sent to wrong person:", mail.To)
	}

	if mail.Subject != "Add 2FA to Account" {
		t.Error("subject wrong:", mail.Subject)
	}

	urlRgx := regexp.MustCompile(`^http://localhost:8080/auth/2fa/totp/email/verify/end\?token=[\-_a-zA-Z0-9=%]+$`)

	data := h.renderer.Data
	if !urlRgx.MatchString(data[DataVerifyURL].(string)) {
		t.Error("url is wrong:", data[DataVerifyURL])
	}
}

func TestEmailVerifyEnd(t *testing.T) {
	t.Parallel()

	h := testEmailVerifySetup()

	rec := httptest.NewRecorder()
	r := mocks.Request("POST")
	w := h.ab.NewResponse(rec)

	h.bodyReader.Return = mocks.Values{Token: "abc"}

	h.session.ClientValues[authboss.Session2FAAuthToken] = "abc"
	h.loadClientState(w, &r)

	if err := h.emailverify.End(w, r); err != nil {
		t.Error(err)
	}

	ro := h.redirector.Options
	if ro.Code != http.StatusTemporaryRedirect {
		t.Error("code wrong:", ro.Code)
	}

	if ro.RedirectPath != "/2fa/totp/setup" {
		t.Error("redir path wrong:", ro.RedirectPath)
	}

	// Flush session state
	w.WriteHeader(http.StatusOK)

	if h.session.ClientValues[authboss.Session2FAAuthed] != "true" {
		t.Error("authed value not set")
	}

	if h.session.ClientValues[authboss.Session2FAAuthToken] != "" {
		t.Error("auth token not removed")
	}
}

func TestEmailVerifyEndFail(t *testing.T) {
	t.Parallel()

	h := testEmailVerifySetup()

	rec := httptest.NewRecorder()
	r := mocks.Request("POST")
	w := h.ab.NewResponse(rec)

	h.bodyReader.Return = mocks.Values{Token: "abc"}

	h.session.ClientValues[authboss.Session2FAAuthToken] = "notabc"
	h.loadClientState(w, &r)

	if err := h.emailverify.End(w, r); err != nil {
		t.Error(err)
	}

	ro := h.redirector.Options
	if ro.Code != http.StatusTemporaryRedirect {
		t.Error("code wrong:", ro.Code)
	}

	if ro.RedirectPath != "/" {
		t.Error("redir path wrong:", ro.RedirectPath)
	}

	if ro.Failure != h.ab.Localizef(context.Background(), authboss.TxtInvalid2FAVerificationToken) {
		t.Error("did not get correct failure")
	}

	if h.session.ClientValues[authboss.Session2FAAuthed] != "" {
		t.Error("should not be authed")
	}
}

func TestEmailVerifyWrap(t *testing.T) {
	t.Parallel()

	t.Run("NotRequired", func(t *testing.T) {
		h := testEmailVerifySetup()

		rec := httptest.NewRecorder()
		r := mocks.Request("POST")
		w := h.ab.NewResponse(rec)

		h.ab.Config.Modules.TwoFactorEmailAuthRequired = false

		called := false
		server := h.emailverify.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		server.ServeHTTP(w, r)
		if !called {
			t.Error("should have called the handler")
		}
	})
	t.Run("Success", func(t *testing.T) {
		h := testEmailVerifySetup()

		rec := httptest.NewRecorder()
		r := mocks.Request("POST")
		w := h.ab.NewResponse(rec)

		h.session.ClientValues[authboss.Session2FAAuthed] = "true"
		h.loadClientState(w, &r)

		called := false
		server := h.emailverify.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		server.ServeHTTP(w, r)
		if !called {
			t.Error("should have called the handler")
		}
	})
	t.Run("Fail", func(t *testing.T) {
		h := testEmailVerifySetup()

		rec := httptest.NewRecorder()
		r := mocks.Request("POST")
		w := h.ab.NewResponse(rec)

		called := false
		server := h.emailverify.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		server.ServeHTTP(w, r)
		if called {
			t.Error("should not have called the handler")
		}

		ro := h.redirector.Options
		if ro.Code != http.StatusTemporaryRedirect {
			t.Error("code wrong:", ro.Code)
		}

		if ro.RedirectPath != "/auth/2fa/totp/email/verify" {
			t.Error("redir path wrong:", ro.RedirectPath)
		}

		if ro.Failure != h.ab.Localizef(context.Background(), authboss.Txt2FAAuthorizationRequired) {
			t.Error("did not get correct failure")
		}
	})
}
