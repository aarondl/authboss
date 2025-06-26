package expire

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aarondl/authboss/v3"
	"github.com/aarondl/authboss/v3/mocks"
)

func TestExpireSetup(t *testing.T) {
	ab := authboss.New()

	clientRW := mocks.NewClientRW()
	ab.Storage.SessionState = clientRW

	Setup(ab)

	w := httptest.NewRecorder()
	wr := ab.NewResponse(w)

	handled, err := ab.Events.FireAfter(authboss.EventAuth, wr, nil)
	if handled {
		t.Error("it should not handle the event")
	}
	if err != nil {
		t.Error(err)
	}

	wr.WriteHeader(http.StatusOK)
	if _, ok := clientRW.ClientValues[authboss.SessionLastAction]; !ok {
		t.Error("last action should have been set")
	}
}

func TestExpireIsExpired(t *testing.T) {
	ab := authboss.New()

	clientRW := mocks.NewClientRW()
	clientRW.ClientValues[authboss.SessionKey] = "username"
	clientRW.ClientValues[authboss.SessionLastAction] = time.Now().UTC().Format(time.RFC3339)
	ab.Storage.SessionState = clientRW

	r := httptest.NewRequest("GET", "/", nil)
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyPID, "primaryid"))
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, struct{}{}))
	w := ab.NewResponse(httptest.NewRecorder())
	r, err := ab.LoadClientState(w, r)
	if err != nil {
		t.Error(err)
	}

	// No t.Parallel() - Also must be after refreshExpiry() call
	nowTime = func() time.Time {
		return time.Now().UTC().Add(time.Hour * 2)
	}
	defer func() {
		nowTime = time.Now
	}()

	called := false
	hadUser := false
	m := Middleware(ab)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true

		if r.Context().Value(authboss.CTXKeyPID) != nil {
			hadUser = true
		}
		if r.Context().Value(authboss.CTXKeyUser) != nil {
			hadUser = true
		}
	}))

	m.ServeHTTP(w, r)

	if !called {
		t.Error("expected middleware to call handler")
	}
	if hadUser {
		t.Error("expected user not to be present")
	}

	w.WriteHeader(200)
	if _, ok := clientRW.ClientValues[authboss.SessionKey]; ok {
		t.Error("this key should have been deleted\n", clientRW)
	}
	if _, ok := clientRW.ClientValues[authboss.SessionLastAction]; ok {
		t.Error("this key should have been deleted\n", clientRW)
	}
}

func TestExpireNotExpired(t *testing.T) {
	ab := authboss.New()
	clientRW := mocks.NewClientRW()
	clientRW.ClientValues[authboss.SessionKey] = "username"
	clientRW.ClientValues[authboss.SessionLastAction] = time.Now().UTC().Format(time.RFC3339)
	ab.Storage.SessionState = clientRW

	var err error

	r := httptest.NewRequest("GET", "/", nil)
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyPID, "primaryid"))
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, struct{}{}))
	w := ab.NewResponse(httptest.NewRecorder())
	r, err = ab.LoadClientState(w, r)
	if err != nil {
		t.Error(err)
	}

	// No t.Parallel() - Also must be after refreshExpiry() call
	newTime := time.Now().UTC().Add(ab.Modules.ExpireAfter / 2)
	nowTime = func() time.Time {
		return newTime
	}
	defer func() {
		nowTime = time.Now
	}()

	called := false
	hadUser := true
	m := Middleware(ab)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true

		if r.Context().Value(authboss.CTXKeyPID) == nil {
			hadUser = false
		}
		if r.Context().Value(authboss.CTXKeyUser) == nil {
			hadUser = false
		}
	}))

	m.ServeHTTP(w, r)

	if !called {
		t.Error("expected middleware to call handler")
	}
	if !hadUser {
		t.Error("expected user to be present")
	}

	want := newTime.Format(time.RFC3339)
	w.WriteHeader(200)
	if last, ok := clientRW.ClientValues[authboss.SessionLastAction]; !ok {
		t.Error("this key should be present", clientRW)
	} else if want != last {
		t.Error("want:", want, "got:", last)
	}
}

func TestExpireTimeToExpiry(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest("GET", "/", nil)

	want := 5 * time.Second
	dur := TimeToExpiry(r, want)
	if dur != want {
		t.Error("duration was wrong:", dur)
	}
}

func TestExpireRefreshExpiry(t *testing.T) {
	t.Parallel()

	ab := authboss.New()
	clientRW := mocks.NewClientRW()
	ab.Storage.SessionState = clientRW
	r := httptest.NewRequest("GET", "/", nil)
	w := ab.NewResponse(httptest.NewRecorder())

	RefreshExpiry(w, r)
	w.WriteHeader(200)
	if _, ok := clientRW.ClientValues[authboss.SessionLastAction]; !ok {
		t.Error("this key should have been set")
	}
}
