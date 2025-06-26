package otp

import (
	"crypto/sha512"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aarondl/authboss/v3"
	"github.com/aarondl/authboss/v3/mocks"
)

type testUser struct {
	PID  string
	OTPs string
}

func (t *testUser) GetPID() string      { return t.PID }
func (t *testUser) PutPID(pid string)   { t.PID = pid }
func (t *testUser) GetOTPs() string     { return t.OTPs }
func (t *testUser) PutOTPs(otps string) { t.OTPs = otps }

func TestMustBeOTPable(t *testing.T) {
	t.Parallel()

	var user authboss.User = &testUser{}
	_ = MustBeOTPable(user)
}

func TestInit(t *testing.T) {
	t.Parallel()

	ab := authboss.New()
	router := &mocks.Router{}
	renderer := &mocks.Renderer{}
	errHandler := &mocks.ErrorHandler{}

	ab.Config.Core.Router = router
	ab.Config.Core.ViewRenderer = renderer
	ab.Config.Core.ErrorHandler = errHandler

	o := &OTP{}
	if err := o.Init(ab); err != nil {
		t.Fatal(err)
	}

	routes := []string{"/otp/login", "/otp/add", "/otp/clear"}
	if err := router.HasGets(routes...); err != nil {
		t.Error(err)
	}
	if err := router.HasPosts(routes...); err != nil {
		t.Error(err)
	}
}

func TestLoginGet(t *testing.T) {
	t.Parallel()

	ab := authboss.New()
	responder := &mocks.Responder{}
	ab.Config.Core.Responder = responder

	a := &OTP{ab}

	r := mocks.Request("POST")
	r.URL.RawQuery = "redir=/redirectpage"
	a.LoginGet(nil, r)

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
	otp *OTP
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

	harness.ab.Config.Paths.AuthLoginOK = "/login/ok"

	harness.ab.Config.Core.BodyReader = harness.bodyReader
	harness.ab.Config.Core.Logger = mocks.Logger{}
	harness.ab.Config.Core.Responder = harness.responder
	harness.ab.Config.Core.Redirector = harness.redirector
	harness.ab.Config.Storage.SessionState = harness.session
	harness.ab.Config.Storage.Server = harness.storer

	harness.otp = &OTP{harness.ab}

	return harness
}

func TestLoginPostSuccess(t *testing.T) {
	t.Parallel()

	setupMore := func(h *testHarness) *testHarness {
		h.bodyReader.Return = mocks.Values{
			PID:      "test@test.com",
			Password: "3cc94671-958a912d-bd5a3ba7-3326a380",
		}
		h.storer.Users["test@test.com"] = &mocks.User{
			Email: "test@test.com",
			// 3cc94671-958a912d-bd5a3ba7-3326a380
			OTPs: "2aID,2aIDHxmTIy1W7Uyz9c+iqhOJSE0a2Yna3zTRTs2q/X7Bv3xdVjExoztBEG4sQ2Nn3jcaPxdIuhslvSsjaYK5uA==",
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

		if err := h.otp.LoginPost(w, r); err != nil {
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

		// Remaining length of the chunk of base64 is 4 characters
		if len(h.storer.Users["test@test.com"].OTPs) != 4 {
			t.Error("the user should have used one of his OTPs")
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

		if err := h.otp.LoginPost(w, r); err != nil {
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

		if err := h.otp.LoginPost(w, r); err != nil {
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

func TestLoginPostBadPassword(t *testing.T) {
	t.Parallel()

	setupMore := func(h *testHarness) *testHarness {
		h.bodyReader.Return = mocks.Values{
			PID:      "test@test.com",
			Password: "nope",
		}
		h.storer.Users["test@test.com"] = &mocks.User{
			Email:    "test@test.com",
			Password: "", // hello world
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

		if err := h.otp.LoginPost(w, r); err != nil {
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

		if err := h.otp.LoginPost(w, r); err != nil {
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

	// This event is really the only thing that separates
	// "user not found" from "bad password"
	var afterCalled bool
	harness.ab.Events.After(authboss.EventAuthFail, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
		afterCalled = true
		return false, nil
	})

	if err := harness.otp.LoginPost(w, r); err != nil {
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

func TestAddGet(t *testing.T) {
	t.Parallel()

	h := testSetup()
	h.storer.Users["test@test.com"] = &mocks.User{
		Email: "test@test.com",
		// 3cc94671-958a912d-bd5a3ba7-3326a380
		OTPs: "2aID,2aIDHxmTIy1W7Uyz9c+iqhOJSE0a2Yna3zTRTs2q/X7Bv3xdVjExoztBEG4sQ2Nn3jcaPxdIuhslvSsjaYK5uA==",
	}
	h.session.ClientValues[authboss.SessionKey] = "test@test.com"

	r := mocks.Request("POST")
	w := h.ab.NewResponse(httptest.NewRecorder())

	var err error
	r, err = h.ab.LoadClientState(w, r)
	if err != nil {
		t.Fatal(err)
	}

	if err := h.otp.AddGet(w, r); err != nil {
		t.Fatal(err)
	}

	if h.responder.Page != PageAdd {
		t.Error("wanted add page, got:", h.responder.Page)
	}

	if h.responder.Status != http.StatusOK {
		t.Error("wanted ok status, got:", h.responder.Status)
	}

	if ln := h.responder.Data[DataNumberOTPs]; ln != "2" {
		t.Error("want two otps:", ln)
	}
}

func TestAddPost(t *testing.T) {
	t.Parallel()

	h := testSetup()
	uname := "test@test.com"
	h.storer.Users[uname] = &mocks.User{
		Email: uname,
		// 3cc94671-958a912d-bd5a3ba7-3326a380
		OTPs: "2aID,2aIDHxmTIy1W7Uyz9c+iqhOJSE0a2Yna3zTRTs2q/X7Bv3xdVjExoztBEG4sQ2Nn3jcaPxdIuhslvSsjaYK5uA==",
	}
	h.session.ClientValues[authboss.SessionKey] = uname

	r := mocks.Request("POST")
	w := h.ab.NewResponse(httptest.NewRecorder())

	var err error
	r, err = h.ab.LoadClientState(w, r)
	if err != nil {
		t.Fatal(err)
	}

	if err := h.otp.AddPost(w, r); err != nil {
		t.Fatal(err)
	}

	if h.responder.Page != PageAdd {
		t.Error("wanted add page, got:", h.responder.Page)
	}

	if h.responder.Status != http.StatusOK {
		t.Error("wanted ok status, got:", h.responder.Status)
	}

	sum := sha512.Sum512([]byte(h.responder.Data[DataOTP].(string)))
	encoded := base64.StdEncoding.EncodeToString(sum[:])

	otps := splitOTPs(h.storer.Users[uname].OTPs)
	if len(otps) != 3 || encoded != otps[2] {
		t.Error("expected one new otp to be appended to the end")
	}
}

func TestAddPostTooMany(t *testing.T) {
	t.Parallel()

	h := testSetup()
	uname := "test@test.com"
	h.storer.Users[uname] = &mocks.User{
		Email: uname,
		OTPs:  "2aID,2aID,2aID,2aID,2aID",
	}
	h.session.ClientValues[authboss.SessionKey] = uname

	r := mocks.Request("POST")
	w := h.ab.NewResponse(httptest.NewRecorder())

	var err error
	r, err = h.ab.LoadClientState(w, r)
	if err != nil {
		t.Fatal(err)
	}

	if err := h.otp.AddPost(w, r); err != nil {
		t.Fatal(err)
	}

	if h.responder.Page != PageAdd {
		t.Error("wanted add page, got:", h.responder.Page)
	}
	if h.responder.Status != http.StatusOK {
		t.Error("wanted ok status, got:", h.responder.Status)
	}
	if len(h.responder.Data[authboss.DataValidation].(string)) == 0 {
		t.Error("there should have been a validation error")
	}

	otps := splitOTPs(h.storer.Users[uname].OTPs)
	if len(otps) != maxOTPs {
		t.Error("expected the number of OTPs to be equal to the maximum")
	}
}

func TestAddGetUserNotFound(t *testing.T) {
	t.Parallel()

	h := testSetup()

	r := mocks.Request("GET")
	w := h.ab.NewResponse(httptest.NewRecorder())

	if err := h.otp.AddGet(w, r); err != authboss.ErrUserNotFound {
		t.Error("it should have failed with user not found")
	}
}

func TestAddPostUserNotFound(t *testing.T) {
	t.Parallel()

	h := testSetup()

	r := mocks.Request("POST")
	w := h.ab.NewResponse(httptest.NewRecorder())

	if err := h.otp.AddPost(w, r); err != authboss.ErrUserNotFound {
		t.Error("it should have failed with user not found")
	}
}

func TestClearGet(t *testing.T) {
	t.Parallel()

	h := testSetup()

	h.storer.Users["test@test.com"] = &mocks.User{
		Email: "test@test.com",
		// 3cc94671-958a912d-bd5a3ba7-3326a380
		OTPs: "2aID,2aIDHxmTIy1W7Uyz9c+iqhOJSE0a2Yna3zTRTs2q/X7Bv3xdVjExoztBEG4sQ2Nn3jcaPxdIuhslvSsjaYK5uA==",
	}
	h.session.ClientValues[authboss.SessionKey] = "test@test.com"

	r := mocks.Request("POST")
	w := h.ab.NewResponse(httptest.NewRecorder())

	var err error
	r, err = h.ab.LoadClientState(w, r)
	if err != nil {
		t.Fatal(err)
	}

	if err := h.otp.ClearGet(w, r); err != nil {
		t.Fatal(err)
	}

	if h.responder.Page != PageClear {
		t.Error("wanted clear page, got:", h.responder.Page)
	}

	if h.responder.Status != http.StatusOK {
		t.Error("wanted ok status, got:", h.responder.Status)
	}

	if ln := h.responder.Data[DataNumberOTPs]; ln != "2" {
		t.Error("want two otps:", ln)
	}
}

func TestClearPost(t *testing.T) {
	t.Parallel()

	h := testSetup()
	uname := "test@test.com"
	h.storer.Users[uname] = &mocks.User{
		Email: uname,
		// 3cc94671-958a912d-bd5a3ba7-3326a380
		OTPs: "2aID,2aIDHxmTIy1W7Uyz9c+iqhOJSE0a2Yna3zTRTs2q/X7Bv3xdVjExoztBEG4sQ2Nn3jcaPxdIuhslvSsjaYK5uA==",
	}
	h.session.ClientValues[authboss.SessionKey] = uname

	r := mocks.Request("POST")
	w := h.ab.NewResponse(httptest.NewRecorder())

	var err error
	r, err = h.ab.LoadClientState(w, r)
	if err != nil {
		t.Fatal(err)
	}

	if err := h.otp.ClearPost(w, r); err != nil {
		t.Fatal(err)
	}

	if h.responder.Page != PageAdd {
		t.Error("wanted add page, got:", h.responder.Page)
	}

	if h.responder.Status != http.StatusOK {
		t.Error("wanted ok status, got:", h.responder.Status)
	}

	otps := splitOTPs(h.storer.Users[uname].OTPs)
	if len(otps) != 0 {
		t.Error("expected all otps to be gone")
	}
}

func TestClearGetUserNotFound(t *testing.T) {
	t.Parallel()

	h := testSetup()

	r := mocks.Request("GET")
	w := h.ab.NewResponse(httptest.NewRecorder())

	if err := h.otp.ClearGet(w, r); err != authboss.ErrUserNotFound {
		t.Error("it should have failed with user not found")
	}
}

func TestClearPostUserNotFound(t *testing.T) {
	t.Parallel()

	h := testSetup()

	r := mocks.Request("POST")
	w := h.ab.NewResponse(httptest.NewRecorder())

	if err := h.otp.AddPost(w, r); err != authboss.ErrUserNotFound {
		t.Error("it should have failed with user not found")
	}
}
