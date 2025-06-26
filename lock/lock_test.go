package lock

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aarondl/authboss/v3"
	"github.com/aarondl/authboss/v3/mocks"
)

func TestInit(t *testing.T) {
	t.Parallel()

	ab := authboss.New()

	l := &Lock{}
	if err := l.Init(ab); err != nil {
		t.Fatal(err)
	}
}

type testHarness struct {
	lock *Lock
	ab   *authboss.Authboss

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

	harness.ab.Paths.LockNotOK = "/lock/not/ok"
	harness.ab.Modules.LockAfter = 3
	harness.ab.Modules.LockDuration = time.Hour
	harness.ab.Modules.LockWindow = time.Minute

	harness.ab.Config.Core.BodyReader = harness.bodyReader
	harness.ab.Config.Core.Logger = mocks.Logger{}
	harness.ab.Config.Core.Mailer = harness.mailer
	harness.ab.Config.Core.Redirector = harness.redirector
	harness.ab.Config.Core.MailRenderer = harness.renderer
	harness.ab.Config.Core.Responder = harness.responder
	harness.ab.Config.Storage.SessionState = harness.session
	harness.ab.Config.Storage.Server = harness.storer

	harness.lock = &Lock{harness.ab}

	return harness
}

func TestBeforeAuthAllow(t *testing.T) {
	t.Parallel()

	harness := testSetup()

	user := &mocks.User{
		Email:  "test@test.com",
		Locked: time.Time{},
	}
	harness.storer.Users["test@test.com"] = user

	r := mocks.Request("GET")
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
	w := httptest.NewRecorder()

	handled, err := harness.lock.BeforeAuth(w, r, false)
	if err != nil {
		t.Error(err)
	}
	if handled {
		t.Error("it shouldn't have been handled")
	}
}

func TestBeforeAuthDisallow(t *testing.T) {
	t.Parallel()

	harness := testSetup()

	user := &mocks.User{
		Email:  "test@test.com",
		Locked: time.Now().UTC().Add(time.Hour),
	}
	harness.storer.Users["test@test.com"] = user

	r := mocks.Request("GET")
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
	w := httptest.NewRecorder()

	handled, err := harness.lock.BeforeAuth(w, r, false)
	if err != nil {
		t.Error(err)
	}
	if !handled {
		t.Error("it should have been handled")
	}

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("code was wrong:", w.Code)
	}

	opts := harness.redirector.Options
	if opts.RedirectPath != harness.ab.Paths.LockNotOK {
		t.Error("redir path was wrong:", opts.RedirectPath)
	}

	if len(opts.Failure) == 0 {
		t.Error("expected a failure message")
	}
}

func TestAfterAuthSuccess(t *testing.T) {
	t.Parallel()

	harness := testSetup()

	last := time.Now().UTC().Add(-time.Hour)
	user := &mocks.User{
		Email:        "test@test.com",
		AttemptCount: 45,
		LastAttempt:  last,
	}

	harness.storer.Users["test@test.com"] = user

	r := mocks.Request("GET")
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
	w := httptest.NewRecorder()

	handled, err := harness.lock.AfterAuthSuccess(w, r, false)
	if err != nil {
		t.Error(err)
	}
	if handled {
		t.Error("it should never be handled")
	}

	user = harness.storer.Users["test@test.com"]
	if 0 != user.GetAttemptCount() {
		t.Error("attempt count wrong:", user.GetAttemptCount())
	}
	if !last.Before(user.GetLastAttempt()) {
		t.Errorf("last attempt should be more recent, old: %v new: %v", last, user.GetLastAttempt())
	}
}

func TestAfterAuthFailure(t *testing.T) {
	t.Parallel()

	harness := testSetup()

	user := &mocks.User{
		Email: "test@test.com",
	}
	harness.storer.Users["test@test.com"] = user

	if IsLocked(harness.storer.Users["test@test.com"]) {
		t.Error("should not be locked")
	}

	r := mocks.Request("GET")
	w := httptest.NewRecorder()

	var handled bool
	var err error

	for i := 1; i <= 3; i++ {
		if IsLocked(harness.storer.Users["test@test.com"]) {
			t.Error("should not be locked")
		}

		r := r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
		handled, err = harness.lock.AfterAuthFail(w, r, false)
		if err != nil {
			t.Fatal(err)
		}

		if i < 3 {
			if handled {
				t.Errorf("%d) should not be handled until lock occurs", i)
			}

			user := harness.storer.Users["test@test.com"]
			if user.GetAttemptCount() != i {
				t.Errorf("attempt count wrong, want: %d, got: %d", i, user.GetAttemptCount())
			}
			if IsLocked(user) {
				t.Error("should not be locked")
			}
		}
	}

	if !handled {
		t.Error("should have been handled at the end")
	}

	if !IsLocked(harness.storer.Users["test@test.com"]) {
		t.Error("should be locked at the end")
	}

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("code was wrong:", w.Code)
	}

	opts := harness.redirector.Options
	if opts.RedirectPath != harness.ab.Paths.LockNotOK {
		t.Error("redir path was wrong:", opts.RedirectPath)
	}

	if len(opts.Failure) == 0 {
		t.Error("expected a failure message")
	}
}

func TestLock(t *testing.T) {
	t.Parallel()

	harness := testSetup()

	user := &mocks.User{
		Email: "test@test.com",
	}
	harness.storer.Users["test@test.com"] = user

	if IsLocked(harness.storer.Users["test@test.com"]) {
		t.Error("should not be locked")
	}

	if err := harness.lock.Lock(context.Background(), "test@test.com"); err != nil {
		t.Error(err)
	}

	if !IsLocked(harness.storer.Users["test@test.com"]) {
		t.Error("should be locked")
	}
}

func TestUnlock(t *testing.T) {
	t.Parallel()

	harness := testSetup()

	user := &mocks.User{
		Email:  "test@test.com",
		Locked: time.Now().UTC().Add(time.Hour),
	}
	harness.storer.Users["test@test.com"] = user

	if !IsLocked(harness.storer.Users["test@test.com"]) {
		t.Error("should be locked")
	}

	if err := harness.lock.Unlock(context.Background(), "test@test.com"); err != nil {
		t.Error(err)
	}

	if IsLocked(harness.storer.Users["test@test.com"]) {
		t.Error("should no longer be locked")
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
		Locked: time.Now().UTC().Add(-time.Hour),
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
	ab.Config.Paths.LockNotOK = "/lock/not/ok"
	ab.Config.Core.Logger = mocks.Logger{}
	ab.Config.Core.Redirector = redirector

	called := false
	server := Middleware(ab)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	user := &mocks.User{
		Locked: time.Now().UTC().Add(time.Hour),
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
	if p := redirector.Options.RedirectPath; p != "/lock/not/ok" {
		t.Error("redirect path wrong:", p)
	}
}
