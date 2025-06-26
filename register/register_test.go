package register

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/friendsofgo/errors"
	"github.com/aarondl/authboss/v3"
	"github.com/aarondl/authboss/v3/mocks"
)

func TestRegisterInit(t *testing.T) {
	t.Parallel()

	ab := authboss.New()

	router := &mocks.Router{}
	renderer := &mocks.Renderer{}
	errHandler := &mocks.ErrorHandler{}
	ab.Config.Core.Router = router
	ab.Config.Core.ViewRenderer = renderer
	ab.Config.Core.ErrorHandler = errHandler
	ab.Config.Storage.Server = &mocks.ServerStorer{}

	reg := &Register{}
	if err := reg.Init(ab); err != nil {
		t.Fatal(err)
	}

	if err := renderer.HasLoadedViews(PageRegister); err != nil {
		t.Error(err)
	}

	if err := router.HasGets("/register"); err != nil {
		t.Error(err)
	}
	if err := router.HasPosts("/register"); err != nil {
		t.Error(err)
	}
}

func TestRegisterGet(t *testing.T) {
	t.Parallel()

	ab := authboss.New()
	responder := &mocks.Responder{}
	ab.Config.Core.Responder = responder

	a := &Register{ab}
	if err := a.Get(nil, nil); err != nil {
		t.Error(err)
	}

	if responder.Page != PageRegister {
		t.Error("wanted login page, got:", responder.Page)
	}

	if responder.Status != http.StatusOK {
		t.Error("wanted ok status, got:", responder.Status)
	}
}

type testHarness struct {
	reg *Register
	ab  *authboss.Authboss

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

	harness.ab.Paths.RegisterOK = "/ok"

	harness.ab.Config.Core.BodyReader = harness.bodyReader
	harness.ab.Config.Core.Logger = mocks.Logger{}
	harness.ab.Config.Core.Hasher = mocks.Hasher{}
	harness.ab.Config.Core.Responder = harness.responder
	harness.ab.Config.Core.Redirector = harness.redirector
	harness.ab.Config.Storage.SessionState = harness.session
	harness.ab.Config.Storage.Server = harness.storer

	harness.reg = &Register{harness.ab}

	return harness
}

func TestRegisterPostSuccess(t *testing.T) {
	t.Parallel()

	setupMore := func(harness *testHarness) *testHarness {
		harness.ab.Modules.RegisterPreserveFields = []string{"email", "another"}
		harness.bodyReader.Return = mocks.ArbValues{
			Values: map[string]string{
				"email":    "test@test.com",
				"password": "hello world",
				"another":  "value",
			},
		}

		return harness
	}

	t.Run("normal", func(t *testing.T) {
		t.Parallel()
		h := setupMore(testSetup())

		r := mocks.Request("POST")
		resp := httptest.NewRecorder()
		w := h.ab.NewResponse(resp)

		if err := h.reg.Post(w, r); err != nil {
			t.Error(err)
		}

		user, ok := h.storer.Users["test@test.com"]
		if !ok {
			t.Error("user was not persisted in the DB")
		}
		if err := h.ab.Config.Core.Hasher.CompareHashAndPassword(user.Password, "hello world"); err != nil {
			t.Error("password was not properly encrypted:", err)
		}

		if user.Arbitrary["another"] != "value" {
			t.Error("arbitrary values not saved")
		}

		if h.session.ClientValues[authboss.SessionKey] != "test@test.com" {
			t.Error("user should have been logged in:", h.session.ClientValues)
		}

		if resp.Code != http.StatusTemporaryRedirect {
			t.Error("code was wrong:", resp.Code)
		}
		if h.redirector.Options.RedirectPath != "/ok" {
			t.Error("redirect path was wrong:", h.redirector.Options.RedirectPath)
		}
	})

	t.Run("handledAfter", func(t *testing.T) {
		t.Parallel()
		h := setupMore(testSetup())

		var afterCalled bool
		h.ab.Events.After(authboss.EventRegister, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
			w.WriteHeader(http.StatusTeapot)
			afterCalled = true
			return true, nil
		})

		r := mocks.Request("POST")
		resp := httptest.NewRecorder()
		w := h.ab.NewResponse(resp)

		if err := h.reg.Post(w, r); err != nil {
			t.Error(err)
		}

		user, ok := h.storer.Users["test@test.com"]
		if !ok {
			t.Error("user was not persisted in the DB")
		}
		if err := h.ab.Config.Core.Hasher.CompareHashAndPassword(user.Password, "hello world"); err != nil {
			t.Error("password was not properly encrypted:", err)
		}

		if val, ok := h.session.ClientValues[authboss.SessionKey]; ok {
			t.Error("user should not have been logged in:", val)
		}

		if resp.Code != http.StatusTeapot {
			t.Error("code was wrong:", resp.Code)
		}

		if !afterCalled {
			t.Error("the after handler should have been called")
		}
	})
}

func TestRegisterPostValidationFailure(t *testing.T) {
	t.Parallel()

	h := testSetup()

	// Ensure the below is sorted, the sort normally happens in Init()
	// that we don't call
	h.ab.Modules.RegisterPreserveFields = []string{"another", "email"}
	h.bodyReader.Return = mocks.ArbValues{
		Values: map[string]string{
			"email":    "test@test.com",
			"password": "hello world",
			"another":  "value",
		},
		Errors: []error{
			errors.New("bad password"),
		},
	}

	r := mocks.Request("POST")
	resp := httptest.NewRecorder()
	w := h.ab.NewResponse(resp)

	if err := h.reg.Post(w, r); err != nil {
		t.Error(err)
	}

	if h.responder.Status != http.StatusOK {
		t.Error("wrong status:", h.responder.Status)
	}
	if h.responder.Page != PageRegister {
		t.Error("rendered wrong page:", h.responder.Page)
	}

	errList := h.responder.Data[authboss.DataValidation].(map[string][]string)
	if e := errList[""][0]; e != "bad password" {
		t.Error("validation error wrong:", e)
	}

	intfD, ok := h.responder.Data[authboss.DataPreserve]
	if !ok {
		t.Fatal("there was no preserved data")
	}

	d := intfD.(map[string]string)
	if d["email"] != "test@test.com" {
		t.Error("e-mail was not preserved:", d)
	} else if d["another"] != "value" {
		t.Error("another value was not preserved", d)
	} else if _, ok = d["password"]; ok {
		t.Error("password was preserved", d)
	}
}

func TestRegisterPostUserExists(t *testing.T) {
	t.Parallel()

	h := testSetup()

	// Ensure the below is sorted, the sort normally happens in Init()
	// that we don't call
	h.ab.Modules.RegisterPreserveFields = []string{"another", "email"}
	h.storer.Users["test@test.com"] = &mocks.User{}
	h.bodyReader.Return = mocks.ArbValues{
		Values: map[string]string{
			"email":    "test@test.com",
			"password": "hello world",
			"another":  "value",
		},
	}

	r := mocks.Request("POST")
	resp := httptest.NewRecorder()
	w := h.ab.NewResponse(resp)

	if err := h.reg.Post(w, r); err != nil {
		t.Error(err)
	}

	if h.responder.Status != http.StatusOK {
		t.Error("wrong status:", h.responder.Status)
	}
	if h.responder.Page != PageRegister {
		t.Error("rendered wrong page:", h.responder.Page)
	}

	errList := h.responder.Data[authboss.DataValidation].(map[string][]string)
	if e := errList[""][0]; e != h.ab.Localizef(context.Background(), authboss.TxtUserAlreadyExists) {
		t.Error("validation error wrong:", e)
	}

	intfD, ok := h.responder.Data[authboss.DataPreserve]
	if !ok {
		t.Fatal("there was no preserved data")
	}

	d := intfD.(map[string]string)
	if d["email"] != "test@test.com" {
		t.Error("e-mail was not preserved:", d)
	} else if d["another"] != "value" {
		t.Error("another value was not preserved", d)
	} else if _, ok = d["password"]; ok {
		t.Error("password was preserved", d)
	}
}

func TestHasString(t *testing.T) {
	t.Parallel()

	strs := []string{"b", "c", "d", "e"}

	if !hasString(strs, "b") {
		t.Error("should have a")
	}
	if !hasString(strs, "e") {
		t.Error("should have d")
	}

	if hasString(strs, "a") {
		t.Error("should not have a")
	}
	if hasString(strs, "f") {
		t.Error("should not have f")
	}
}
