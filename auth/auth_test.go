package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aarondl/authboss/v3"
	"github.com/aarondl/authboss/v3/mocks"
)

func TestAuthInit(t *testing.T) {
	t.Parallel()

	ab := authboss.New()

	router := &mocks.Router{}
	renderer := &mocks.Renderer{}
	errHandler := &mocks.ErrorHandler{}
	ab.Config.Core.Router = router
	ab.Config.Core.ViewRenderer = renderer
	ab.Config.Core.ErrorHandler = errHandler

	a := &Auth{}
	if err := a.Init(ab); err != nil {
		t.Fatal(err)
	}

	if err := renderer.HasLoadedViews(PageLogin); err != nil {
		t.Error(err)
	}

	if err := router.HasGets("/login"); err != nil {
		t.Error(err)
	}
	if err := router.HasPosts("/login"); err != nil {
		t.Error(err)
	}
}

func TestAuthGet(t *testing.T) {
	t.Parallel()

	ab := authboss.New()
	responder := &mocks.Responder{}
	ab.Config.Core.Responder = responder

	a := &Auth{ab}

	r := mocks.Request("GET")
	r.URL.RawQuery = "redir=/redirectpage"
	if err := a.LoginGet(nil, r); err != nil {
		t.Error(err)
	}

	if responder.Page != PageLogin {
		t.Error("wanted login page, got:", responder.Page)
	}

	if responder.Status != http.StatusOK {
		t.Error("wanted ok status, got:", responder.Status)
	}

	if got := responder.Data[authboss.FormValueRedirect]; got != "/redirectpage" {
		t.Error("redirect page was wrong:", got)
	}
}

type testHarness struct {
	auth *Auth
	ab   *authboss.Authboss

	bodyReader *mocks.BodyReader
	responder  *mocks.Responder
	redirector *mocks.Redirector
	session    *mocks.ClientStateRW
	storer     *mocks.ServerStorer
}

func testSetup() *testHarness {
	harness := &testHarness{}

	harness.ab = authboss.New()
	harness.bodyReader = &mocks.BodyReader{}
	harness.redirector = &mocks.Redirector{}
	harness.responder = &mocks.Responder{}
	harness.session = mocks.NewClientRW()
	harness.storer = mocks.NewServerStorer()

	harness.ab.Paths.AuthLoginOK = "/login/ok"

	harness.ab.Config.Core.BodyReader = harness.bodyReader
	harness.ab.Config.Core.Logger = mocks.Logger{}
	harness.ab.Config.Core.Hasher = mocks.Hasher{}
	harness.ab.Config.Core.Responder = harness.responder
	harness.ab.Config.Core.Redirector = harness.redirector
	harness.ab.Config.Storage.SessionState = harness.session
	harness.ab.Config.Storage.Server = harness.storer

	harness.auth = &Auth{harness.ab}

	return harness
}

func TestAuthPostSuccess(t *testing.T) {
	t.Parallel()

	setupMore := func(h *testHarness) *testHarness {
		h.bodyReader.Return = mocks.Values{
			PID:      "test@test.com",
			Password: "hello world",
		}
		h.storer.Users["test@test.com"] = &mocks.User{
			Email:    "test@test.com",
			Password: "$2a$10$IlfnqVyDZ6c1L.kaA/q3bu1nkAC6KukNUsizvlzay1pZPXnX2C9Ji", // hello world
		}
		h.session.ClientValues[authboss.SessionHalfAuthKey] = "true"

		return h
	}

	t.Run("normal", func(t *testing.T) {
		t.Parallel()
		h := setupMore(testSetup())

		var beforeCalled, afterCalled bool
		var beforeHasValues, afterHasValues bool
		h.ab.Events.Before(authboss.EventAuth, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
			beforeCalled = true
			beforeHasValues = r.Context().Value(authboss.CTXKeyValues) != nil
			return false, nil
		})
		h.ab.Events.After(authboss.EventAuth, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
			afterCalled = true
			afterHasValues = r.Context().Value(authboss.CTXKeyValues) != nil
			return false, nil
		})

		r := mocks.Request("POST")
		resp := httptest.NewRecorder()
		w := h.ab.NewResponse(resp)

		if err := h.auth.LoginPost(w, r); err != nil {
			t.Error(err)
		}

		if resp.Code != http.StatusTemporaryRedirect {
			t.Error("code was wrong:", resp.Code)
		}
		if h.redirector.Options.RedirectPath != "/login/ok" {
			t.Error("redirect path was wrong:", h.redirector.Options.RedirectPath)
		}

		if _, ok := h.session.ClientValues[authboss.SessionHalfAuthKey]; ok {
			t.Error("half auth should have been deleted")
		}
		if pid := h.session.ClientValues[authboss.SessionKey]; pid != "test@test.com" {
			t.Error("pid was wrong:", pid)
		}

		if !beforeCalled {
			t.Error("before should have been called")
		}
		if !afterCalled {
			t.Error("after should have been called")
		}
		if !beforeHasValues {
			t.Error("before callback should have access to values")
		}
		if !afterHasValues {
			t.Error("after callback should have access to values")
		}
	})

	t.Run("handledBefore", func(t *testing.T) {
		t.Parallel()
		h := setupMore(testSetup())

		var beforeCalled bool
		h.ab.Events.Before(authboss.EventAuth, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
			w.WriteHeader(http.StatusTeapot)
			beforeCalled = true
			return true, nil
		})

		r := mocks.Request("POST")
		resp := httptest.NewRecorder()
		w := h.ab.NewResponse(resp)

		if err := h.auth.LoginPost(w, r); err != nil {
			t.Error(err)
		}

		if h.responder.Status != 0 {
			t.Error("a status should never have been sent back")
		}
		if _, ok := h.session.ClientValues[authboss.SessionKey]; ok {
			t.Error("session key should not have been set")
		}

		if !beforeCalled {
			t.Error("before should have been called")
		}
		if resp.Code != http.StatusTeapot {
			t.Error("should have left the response alone once teapot was sent")
		}
	})

	t.Run("handledAfter", func(t *testing.T) {
		t.Parallel()
		h := setupMore(testSetup())

		var afterCalled bool
		h.ab.Events.After(authboss.EventAuth, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
			w.WriteHeader(http.StatusTeapot)
			afterCalled = true
			return true, nil
		})

		r := mocks.Request("POST")
		resp := httptest.NewRecorder()
		w := h.ab.NewResponse(resp)

		if err := h.auth.LoginPost(w, r); err != nil {
			t.Error(err)
		}

		if h.responder.Status != 0 {
			t.Error("a status should never have been sent back")
		}
		if _, ok := h.session.ClientValues[authboss.SessionKey]; !ok {
			t.Error("session key should have been set")
		}

		if !afterCalled {
			t.Error("after should have been called")
		}
		if resp.Code != http.StatusTeapot {
			t.Error("should have left the response alone once teapot was sent")
		}
	})
}

func TestAuthPostBadPassword(t *testing.T) {
	t.Parallel()

	setupMore := func(h *testHarness) *testHarness {
		h.bodyReader.Return = mocks.Values{
			PID:      "test@test.com",
			Password: "world hello",
		}
		h.storer.Users["test@test.com"] = &mocks.User{
			Email:    "test@test.com",
			Password: "$2a$10$IlfnqVyDZ6c1L.kaA/q3bu1nkAC6KukNUsizvlzay1pZPXnX2C9Ji", // hello world
		}

		return h
	}

	t.Run("normal", func(t *testing.T) {
		t.Parallel()
		h := setupMore(testSetup())

		r := mocks.Request("POST")
		resp := httptest.NewRecorder()
		w := h.ab.NewResponse(resp)

		var afterCalled bool
		h.ab.Events.After(authboss.EventAuthFail, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
			afterCalled = true
			return false, nil
		})

		if err := h.auth.LoginPost(w, r); err != nil {
			t.Error(err)
		}

		if resp.Code != 200 {
			t.Error("wanted a 200:", resp.Code)
		}

		if h.responder.Data[authboss.DataErr] != "Invalid Credentials" {
			t.Error("wrong error:", h.responder.Data)
		}

		if _, ok := h.session.ClientValues[authboss.SessionKey]; ok {
			t.Error("user should not be logged in")
		}

		if !afterCalled {
			t.Error("after should have been called")
		}
	})

	t.Run("handledAfter", func(t *testing.T) {
		t.Parallel()
		h := setupMore(testSetup())

		r := mocks.Request("POST")
		resp := httptest.NewRecorder()
		w := h.ab.NewResponse(resp)

		var afterCalled bool
		h.ab.Events.After(authboss.EventAuthFail, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
			w.WriteHeader(http.StatusTeapot)
			afterCalled = true
			return true, nil
		})

		if err := h.auth.LoginPost(w, r); err != nil {
			t.Error(err)
		}

		if h.responder.Status != 0 {
			t.Error("responder should not have been called to give a status")
		}
		if _, ok := h.session.ClientValues[authboss.SessionKey]; ok {
			t.Error("user should not be logged in")
		}

		if !afterCalled {
			t.Error("after should have been called")
		}
		if resp.Code != http.StatusTeapot {
			t.Error("should have left the response alone once teapot was sent")
		}
	})
}

func TestAuthPostUserNotFound(t *testing.T) {
	t.Parallel()

	harness := testSetup()
	harness.bodyReader.Return = mocks.Values{
		PID:      "test@test.com",
		Password: "world hello",
	}

	r := mocks.Request("POST")
	resp := httptest.NewRecorder()
	w := harness.ab.NewResponse(resp)

	// This event is really the only thing that separates "user not found"
	// from "bad password"
	var afterCalled bool
	harness.ab.Events.After(authboss.EventAuthFail, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
		afterCalled = true
		return false, nil
	})

	if err := harness.auth.LoginPost(w, r); err != nil {
		t.Error(err)
	}

	if resp.Code != 200 {
		t.Error("wanted a 200:", resp.Code)
	}

	if harness.responder.Data[authboss.DataErr] != "Invalid Credentials" {
		t.Error("wrong error:", harness.responder.Data)
	}

	if _, ok := harness.session.ClientValues[authboss.SessionKey]; ok {
		t.Error("user should not be logged in")
	}

	if afterCalled {
		t.Error("after should not have been called")
	}
}
