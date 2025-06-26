package logout

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aarondl/authboss/v3"
	"github.com/aarondl/authboss/v3/mocks"
)

func TestLogout(t *testing.T) {
	t.Parallel()

	ab := authboss.New()

	router := &mocks.Router{}
	errHandler := &mocks.ErrorHandler{}
	ab.Config.Core.Router = router
	ab.Config.Core.ErrorHandler = errHandler

	l := &Logout{}
	if err := l.Init(ab); err != nil {
		t.Fatal(err)
	}

	if err := router.HasDeletes("/logout"); err != nil {
		t.Error(err)
	}
}

func TestLogoutRoutes(t *testing.T) {
	t.Parallel()

	ab := authboss.New()
	router := &mocks.Router{}
	errHandler := &mocks.ErrorHandler{}
	ab.Config.Core.Router = router
	ab.Config.Core.ErrorHandler = errHandler

	l := &Logout{}
	ab.Config.Modules.LogoutMethod = "what"
	if err := l.Init(ab); err == nil {
		t.Error("should have failed to register the route")
	}

	ab.Config.Modules.LogoutMethod = "GET"
	if err := l.Init(ab); err != nil {
		t.Error("should have failed to register the route")
	}
	if err := router.HasGets("/logout"); err != nil {
		t.Error(err)
	}

	ab.Config.Modules.LogoutMethod = "POST"
	if err := l.Init(ab); err != nil {
		t.Error("should have failed to register the route")
	}
	if err := router.HasPosts("/logout"); err != nil {
		t.Error(err)
	}
}

type testHarness struct {
	logout *Logout
	ab     *authboss.Authboss

	redirector *mocks.Redirector
	session    *mocks.ClientStateRW
	cookies    *mocks.ClientStateRW
	storer     *mocks.ServerStorer
}

func testSetup() *testHarness {
	harness := &testHarness{}

	harness.ab = authboss.New()
	harness.redirector = &mocks.Redirector{}
	harness.session = mocks.NewClientRW()
	harness.cookies = mocks.NewClientRW()
	harness.storer = mocks.NewServerStorer()

	harness.ab.Paths.LogoutOK = "/logout/ok"

	harness.ab.Config.Core.Logger = mocks.Logger{}
	harness.ab.Config.Core.Redirector = harness.redirector
	harness.ab.Config.Storage.SessionState = harness.session
	harness.ab.Config.Storage.CookieState = harness.cookies
	harness.ab.Config.Storage.Server = harness.storer

	harness.logout = &Logout{harness.ab}

	return harness
}

func TestLogoutLogout(t *testing.T) {
	t.Parallel()

	h := testSetup()

	h.session.ClientValues[authboss.SessionKey] = "test@test.com"
	h.session.ClientValues[authboss.SessionHalfAuthKey] = "true"
	h.session.ClientValues[authboss.SessionLastAction] = time.Now().UTC().Format(time.RFC3339)
	h.cookies.ClientValues[authboss.CookieRemember] = "token"

	r := mocks.Request("POST")
	resp := httptest.NewRecorder()
	w := h.ab.NewResponse(resp)

	// This enables the logging portion
	// which is debatable-y not useful in a log out method
	user := &mocks.User{Email: "test@test.com"}
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))

	var err error
	r, err = h.ab.LoadClientState(w, r)
	if err != nil {
		t.Error(err)
	}

	if err := h.logout.Logout(w, r); err != nil {
		t.Fatal(err)
	}

	if resp.Code != http.StatusTemporaryRedirect {
		t.Error("response code wrong:", resp.Code)
	}
	if h.redirector.Options.RedirectPath != "/logout/ok" {
		t.Error("redirect path was wrong:", h.redirector.Options.RedirectPath)
	}

	if _, ok := h.session.ClientValues[authboss.SessionKey]; ok {
		t.Error("want session key gone")
	}
	if _, ok := h.session.ClientValues[authboss.SessionHalfAuthKey]; ok {
		t.Error("want session half auth key gone")
	}
	if _, ok := h.session.ClientValues[authboss.SessionLastAction]; ok {
		t.Error("want session last action")
	}
	if _, ok := h.cookies.ClientValues[authboss.CookieRemember]; ok {
		t.Error("want remember me cookies gone")
	}
}
