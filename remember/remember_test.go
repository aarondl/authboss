package remember

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aarondl/authboss/v3"
	"github.com/aarondl/authboss/v3/mocks"
)

func TestInit(t *testing.T) {
	t.Parallel()

	ab := authboss.New()
	r := &Remember{}
	err := r.Init(ab)
	if err != nil {
		t.Fatal(err)
	}
}

type testHarness struct {
	remember *Remember
	ab       *authboss.Authboss

	session *mocks.ClientStateRW
	cookies *mocks.ClientStateRW
	storer  *mocks.ServerStorer
}

func testSetup() *testHarness {
	harness := &testHarness{}

	harness.ab = authboss.New()
	harness.session = mocks.NewClientRW()
	harness.cookies = mocks.NewClientRW()
	harness.storer = mocks.NewServerStorer()

	harness.ab.Config.Core.Logger = mocks.Logger{}
	harness.ab.Config.Storage.SessionState = harness.session
	harness.ab.Config.Storage.CookieState = harness.cookies
	harness.ab.Config.Storage.Server = harness.storer

	harness.remember = &Remember{harness.ab}

	return harness
}

func TestRememberAfterAuth(t *testing.T) {
	t.Parallel()

	h := testSetup()

	user := &mocks.User{Email: "test@test.com"}

	r := mocks.Request("POST")
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyValues, mocks.Values{Remember: true}))
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
	rec := httptest.NewRecorder()
	w := h.ab.NewResponse(rec)

	if handled, err := h.remember.RememberAfterAuth(w, r, false); err != nil {
		t.Fatal(err)
	} else if handled {
		t.Error("should never be handled")
	}

	// Force flush of headers so cookies are written
	w.WriteHeader(http.StatusOK)

	if len(h.storer.RMTokens["test@test.com"]) != 1 {
		t.Error("token was not persisted:", h.storer.RMTokens)
	}

	if cookie, ok := h.cookies.ClientValues[authboss.CookieRemember]; !ok || len(cookie) == 0 {
		t.Error("remember me cookie was not set")
	}
}

func TestRememberAfterAuthSkip(t *testing.T) {
	t.Parallel()

	h := testSetup()

	r := mocks.Request("POST")
	rec := httptest.NewRecorder()
	w := h.ab.NewResponse(rec)

	if handled, err := h.remember.RememberAfterAuth(w, r, false); err != nil {
		t.Fatal(err)
	} else if handled {
		t.Error("should never be handled")
	}

	if len(h.storer.RMTokens["test@test.com"]) != 0 {
		t.Error("expected no tokens to be created")
	}

	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyValues, mocks.Values{Remember: false}))

	if handled, err := h.remember.RememberAfterAuth(w, r, false); err != nil {
		t.Fatal(err)
	} else if handled {
		t.Error("should never be handled")
	}

	if len(h.storer.RMTokens["test@test.com"]) != 0 {
		t.Error("expected no tokens to be created")
	}
}

func TestMiddlewareAuth(t *testing.T) {
	t.Parallel()

	h := testSetup()

	user := &mocks.User{Email: "test@test.com"}
	hash, token, _ := GenerateToken(user.Email)

	h.storer.Users[user.Email] = user
	h.storer.RMTokens[user.Email] = []string{hash}
	h.cookies.ClientValues[authboss.CookieRemember] = token

	r := mocks.Request("POST")
	rec := httptest.NewRecorder()
	w := h.ab.NewResponse(rec)

	var err error
	r, err = h.ab.LoadClientState(w, r)
	if err != nil {
		t.Fatal(err)
	}

	called := false
	server := Middleware(h.ab)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	server.ServeHTTP(w, r)

	if !called {
		t.Error("it should have called the underlying handler")
	}

	if h.session.ClientValues[authboss.SessionKey] != user.Email {
		t.Error("should have saved the pid in the session")
	}
	// Elided the rest of the checks, authenticate tests do this
}

func TestAuthenticateSuccess(t *testing.T) {
	t.Parallel()

	h := testSetup()

	user := &mocks.User{Email: "test@test.com"}
	hash, token, _ := GenerateToken(user.Email)

	h.storer.Users[user.Email] = user
	h.storer.RMTokens[user.Email] = []string{hash}
	h.cookies.ClientValues[authboss.CookieRemember] = token

	r := mocks.Request("POST")
	rec := httptest.NewRecorder()
	w := h.ab.NewResponse(rec)

	var err error
	r, err = h.ab.LoadClientState(w, r)
	if err != nil {
		t.Fatal(err)
	}

	if err = Authenticate(h.ab, w, &r); err != nil {
		t.Fatal(err)
	}

	w.WriteHeader(http.StatusOK)

	if cookie := h.cookies.ClientValues[authboss.CookieRemember]; cookie == token {
		t.Error("the cookie should have been replaced with a new token")
	}

	if len(h.storer.RMTokens[user.Email]) != 1 {
		t.Error("one token should have been removed, and one should have been added")
	} else if h.storer.RMTokens[user.Email][0] == token {
		t.Error("a new token should have been saved")
	}

	if h.session.ClientValues[authboss.SessionKey] != user.Email {
		t.Error("should have saved the pid in the session")
	}
	if h.session.ClientValues[authboss.SessionHalfAuthKey] != "true" {
		t.Error("it should have become a half-authed session")
	}

	if r.Context().Value(authboss.CTXKeyPID).(string) != "test@test.com" {
		t.Error("should have set the context value to log the user in")
	}
}

func TestAuthenticateTokenNotFound(t *testing.T) {
	t.Parallel()

	h := testSetup()

	user := &mocks.User{Email: "test@test.com"}
	_, token, _ := GenerateToken(user.Email)

	h.storer.Users[user.Email] = user
	h.cookies.ClientValues[authboss.CookieRemember] = token

	r := mocks.Request("POST")
	rec := httptest.NewRecorder()
	w := h.ab.NewResponse(rec)

	var err error
	r, err = h.ab.LoadClientState(w, r)
	if err != nil {
		t.Fatal(err)
	}

	if err = Authenticate(h.ab, w, &r); err != nil {
		t.Fatal(err)
	}

	w.WriteHeader(http.StatusOK)

	if len(h.cookies.ClientValues[authboss.CookieRemember]) != 0 {
		t.Error("there should be no remember cookie left")
	}

	if len(h.session.ClientValues[authboss.SessionKey]) != 0 {
		t.Error("it should have not logged the user in")
	}

	if r.Context().Value(authboss.CTXKeyPID) != nil {
		t.Error("the context's pid should be empty")
	}
}

func TestAuthenticateBadTokens(t *testing.T) {
	t.Parallel()

	h := testSetup()

	doTest := func(t *testing.T) {
		t.Helper()

		r := mocks.Request("POST")
		rec := httptest.NewRecorder()
		w := h.ab.NewResponse(rec)

		var err error
		r, err = h.ab.LoadClientState(w, r)
		if err != nil {
			t.Fatal(err)
		}

		if err = Authenticate(h.ab, w, &r); err != nil {
			t.Fatal(err)
		}

		w.WriteHeader(http.StatusOK)

		if len(h.cookies.ClientValues[authboss.CookieRemember]) != 0 {
			t.Error("there should be no remember cookie left")
		}

		if len(h.session.ClientValues[authboss.SessionKey]) != 0 {
			t.Error("it should have not logged the user in")
		}

		if r.Context().Value(authboss.CTXKeyPID) != nil {
			t.Error("the context's pid should be empty")
		}
	}

	t.Run("base64", func(t *testing.T) {
		h.cookies.ClientValues[authboss.CookieRemember] = "a"
		doTest(t)
	})
	t.Run("cookieformat", func(t *testing.T) {
		h.cookies.ClientValues[authboss.CookieRemember] = `aGVsbG8=` // hello
		doTest(t)
	})
}

func TestAfterPasswordReset(t *testing.T) {
	t.Parallel()

	h := testSetup()

	user := &mocks.User{Email: "test@test.com"}
	hash1, _, _ := GenerateToken(user.Email)
	hash2, token2, _ := GenerateToken(user.Email)

	h.storer.Users[user.Email] = user
	h.storer.RMTokens[user.Email] = []string{hash1, hash2}
	h.cookies.ClientValues[authboss.CookieRemember] = token2

	r := mocks.Request("POST")
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
	rec := httptest.NewRecorder()
	w := h.ab.NewResponse(rec)

	if handled, err := h.remember.AfterPasswordReset(w, r, false); err != nil {
		t.Error(err)
	} else if handled {
		t.Error("it should never be handled")
	}

	w.WriteHeader(http.StatusOK) // Force header flush

	if len(h.storer.RMTokens[user.Email]) != 0 {
		t.Error("all remember me tokens should have been removed")
	}
	if len(h.cookies.ClientValues[authboss.CookieRemember]) != 0 {
		t.Error("there should be no remember cookie left")
	}
}

func TestGenerateToken(t *testing.T) {
	t.Parallel()

	hash, tok, err := GenerateToken("test")
	if err != nil {
		t.Fatal(err)
	}

	rawToken, err := base64.URLEncoding.DecodeString(tok)
	if err != nil {
		t.Error(err)
	}

	index := bytes.IndexByte(rawToken, ';')
	if index < 0 {
		t.Fatalf("problem with the token format: %v", rawToken)
	}

	bytPID := rawToken[:index]
	if string(bytPID) != "test" {
		t.Errorf("pid wrong: %s", bytPID)
	}

	sum := sha512.Sum512(rawToken)
	gotHash := base64.StdEncoding.EncodeToString(sum[:])
	if hash != gotHash {
		t.Errorf("hash wrong, want: %s, got: %s", hash, gotHash)
	}
}
