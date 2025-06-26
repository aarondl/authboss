package totp2fa

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/aarondl/authboss/v3/otp/twofactor"

	"github.com/pquerna/otp/totp"
	"github.com/aarondl/authboss/v3"
	"github.com/aarondl/authboss/v3/mocks"
)

func TestTOTPSetup(t *testing.T) {
	t.Parallel()

	ab := authboss.New()
	router := &mocks.Router{}
	renderer := &mocks.Renderer{}
	errHandler := &mocks.ErrorHandler{}

	ab.Config.Core.Router = router
	ab.Config.Core.ViewRenderer = renderer
	ab.Config.Core.ErrorHandler = errHandler

	totpNew := &TOTP{Authboss: ab}
	if err := totpNew.Setup(); err != nil {
		t.Fatal(err)
	}

	gets := []string{"/2fa/totp/setup", "/2fa/totp/qr", "/2fa/totp/confirm", "/2fa/totp/remove", "/2fa/totp/validate"}
	posts := []string{"/2fa/totp/setup", "/2fa/totp/confirm", "/2fa/totp/remove", "/2fa/totp/validate"}
	if err := router.HasGets(gets...); err != nil {
		t.Error(err)
	}
	if err := router.HasPosts(posts...); err != nil {
		t.Error(err)
	}
}

type testHarness struct {
	totp *TOTP
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

	harness.ab.Config.Paths.AuthLoginOK = "/login/ok"
	harness.ab.Config.Modules.TOTP2FAIssuer = "TOTPTest"

	harness.ab.Config.Core.BodyReader = harness.bodyReader
	harness.ab.Config.Core.Logger = mocks.Logger{}
	harness.ab.Config.Core.Responder = harness.responder
	harness.ab.Config.Core.Redirector = harness.redirector
	harness.ab.Config.Storage.SessionState = harness.session
	harness.ab.Config.Storage.Server = harness.storer

	harness.totp = &TOTP{harness.ab}

	return harness
}

func (h *testHarness) loadClientState(w http.ResponseWriter, r **http.Request) {
	req, err := h.ab.LoadClientState(w, *r)
	if err != nil {
		panic(err)
	}

	*r = req
}

func (h *testHarness) putUserInCtx(u *mocks.User, r **http.Request) {
	req := (*r).WithContext(context.WithValue((*r).Context(), authboss.CTXKeyUser, u))
	*r = req
}

func (h *testHarness) newHTTP(method string, bodyArgs ...string) (*http.Request, *authboss.ClientStateResponseWriter, *httptest.ResponseRecorder) {
	r := mocks.Request(method, bodyArgs...)
	wr := httptest.NewRecorder()
	w := h.ab.NewResponse(wr)

	return r, w, wr
}

func (h *testHarness) setSession(key, value string) {
	h.session.ClientValues[key] = value
}

func TestHijackAuth(t *testing.T) {
	t.Parallel()

	t.Run("Handled", func(t *testing.T) {
		harness := testSetup()

		handled, err := harness.totp.HijackAuth(nil, nil, true)
		if handled {
			t.Error("should not be handled")
		}
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("UserNoTOTP", func(t *testing.T) {
		harness := testSetup()

		r, w, _ := harness.newHTTP("POST")
		r.URL.RawQuery = "test=query"

		user := &mocks.User{Email: "test@test.com"}
		harness.putUserInCtx(user, &r)

		harness.loadClientState(w, &r)
		handled, err := harness.totp.HijackAuth(w, r, false)
		if handled {
			t.Error("should not be handled")
		}
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("Ok", func(t *testing.T) {
		harness := testSetup()

		handled, err := harness.totp.HijackAuth(nil, nil, true)
		if handled {
			t.Error("should not be handled")
		}
		if err != nil {
			t.Error(err)
		}

		r, w, _ := harness.newHTTP("POST")
		r.URL.RawQuery = "test=query"

		user := &mocks.User{Email: "test@test.com", TOTPSecretKey: "secret"}
		harness.putUserInCtx(user, &r)
		harness.loadClientState(w, &r)

		handled, err = harness.totp.HijackAuth(w, r, false)
		if !handled {
			t.Error("should be handled")
		}
		if err != nil {
			t.Error(err)
		}

		opts := harness.redirector.Options
		if opts.Code != http.StatusTemporaryRedirect {
			t.Error("status wrong:", opts.Code)
		}

		if opts.RedirectPath != "/auth/2fa/totp/validate?test=query" {
			t.Error("redir path wrong:", opts.RedirectPath)
		}
	})
}

func TestGetSetup(t *testing.T) {
	t.Parallel()
	h := testSetup()

	r, w, _ := h.newHTTP("GET")

	h.setSession(SessionTOTPSecret, "secret")
	h.loadClientState(w, &r)

	var err error
	if err = h.totp.GetSetup(w, r); err != nil {
		t.Error(err)
	}

	// Flush ClientState
	w.WriteHeader(http.StatusOK)

	if h.session.ClientValues[SessionTOTPSecret] != "" {
		t.Error("session totp secret should be cleared")
	}

	if h.responder.Page != PageTOTPSetup {
		t.Error("page wrong:", h.responder.Page)
	}
}

func TestPostSetup(t *testing.T) {
	t.Parallel()
	h := testSetup()

	r, w, _ := h.newHTTP("GET")
	user := &mocks.User{Email: "test@test.com"}
	h.putUserInCtx(user, &r)

	var err error
	if err = h.totp.PostSetup(w, r); err != nil {
		t.Error(err)
	}

	// Flush ClientState
	w.WriteHeader(http.StatusOK)

	opts := h.redirector.Options
	if opts.Code != http.StatusTemporaryRedirect {
		t.Error("status wrong:", opts.Code)
	}

	if opts.RedirectPath != "/auth/2fa/totp/confirm" {
		t.Error("redir path wrong:", opts.RedirectPath)
	}

	if len(h.session.ClientValues[SessionTOTPSecret]) == 0 {
		t.Error("no secret in the session")
	}
}

func TestGetQRCode(t *testing.T) {
	t.Parallel()
	h := testSetup()

	r, w, wr := h.newHTTP("GET")

	user := &mocks.User{Email: "test@test.com"}
	h.putUserInCtx(user, &r)

	if err := h.totp.GetQRCode(w, r); err == nil {
		t.Error("should fail because there is no totp secret")
	}

	secret := makeSecretKey(h, user.Email)
	h.setSession(SessionTOTPSecret, secret)
	h.loadClientState(w, &r)

	if err := h.totp.GetQRCode(w, r); err != nil {
		t.Error(err)
	}

	if got := wr.Header().Get("Content-Type"); got != "image/png" {
		t.Error("content type wrong:", got)
	}
	if got := wr.Header().Get("Cache-Control"); got != "no-store" {
		t.Error("cache control header wrong:", got)
	}
	if wr.Body.Len() == 0 {
		t.Error("body should have been sizable")
	}
}

func TestGetConfirm(t *testing.T) {
	t.Parallel()
	h := testSetup()

	r, w, _ := h.newHTTP("GET")

	if err := h.totp.GetConfirm(w, r); err == nil {
		t.Error("should fail because there is no totp secret")
	}

	secret := "secret"
	h.setSession(SessionTOTPSecret, secret)
	h.loadClientState(w, &r)

	if err := h.totp.GetConfirm(w, r); err != nil {
		t.Error(err)
	}

	if h.responder.Page != PageTOTPConfirm {
		t.Error("page wrong:", h.responder.Page)
	}
	if got := h.responder.Data[DataTOTPSecret]; got != secret {
		t.Error("data wrong:", got)
	}
}

func TestPostConfirm(t *testing.T) {
	t.Parallel()
	h := testSetup()

	r, w, _ := h.newHTTP("POST")

	if err := h.totp.PostConfirm(w, r); err == nil {
		t.Error("should fail because there is no totp secret")
	}

	user := &mocks.User{Email: "test@test.com"}
	h.storer.Users[user.Email] = user

	secret := makeSecretKey(h, user.Email)
	h.setSession(SessionTOTPSecret, secret)
	h.setSession(authboss.SessionKey, user.Email)
	h.loadClientState(w, &r)

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h.bodyReader.Return = &mocks.Values{Code: code}

	if err = h.totp.PostConfirm(w, r); err != nil {
		t.Error(err)
	}

	// Flush client state
	w.WriteHeader(http.StatusOK)

	if len(user.TOTPSecretKey) == 0 {
		t.Error("totp secret key unset")
	}
	if len(user.RecoveryCodes) == 0 {
		t.Error("user recovery codes unset")
	}
	if _, ok := h.session.ClientValues[SessionTOTPSecret]; ok {
		t.Error("session totp secret not deleted")
	}

	if h.responder.Page != PageTOTPConfirmSuccess {
		t.Error("page wrong:", h.responder.Page)
	}
	if got := h.responder.Data[twofactor.DataRecoveryCodes].([]string); len(got) == 0 {
		t.Error("data wrong:", got)
	}
}

func TestGetRemove(t *testing.T) {
	t.Parallel()
	h := testSetup()

	r, w, _ := h.newHTTP("GET")

	if err := h.totp.GetRemove(w, r); err != nil {
		t.Error(err)
	}

	if h.responder.Page != PageTOTPRemove {
		t.Error("page wrong:", h.responder.Page)
	}
}

func TestPostRemove(t *testing.T) {
	t.Parallel()

	setupMore := func(h *testHarness) *mocks.User {
		user := &mocks.User{Email: "test@test.com"}
		h.storer.Users[user.Email] = user
		h.setSession(authboss.SessionKey, user.Email)

		return user
	}

	t.Run("NoTOTPActivated", func(t *testing.T) {
		h := testSetup()

		r, w, _ := h.newHTTP("POST")
		setupMore(h)
		h.loadClientState(w, &r)

		// No session
		if err := h.totp.PostRemove(w, r); err != nil {
			t.Fatal(err)
		}

		if h.responder.Page != PageTOTPRemove {
			t.Error("page wrong:", h.responder.Page)
		}
		if got := h.responder.Data[authboss.DataErr]; got != h.ab.Localizef(context.Background(), authboss.TxtTOTP2FANotActive) {
			t.Error("data wrong:", got)
		}
	})

	t.Run("WrongCode", func(t *testing.T) {
		h := testSetup()

		r, w, _ := h.newHTTP("POST")

		user := setupMore(h)
		secret := makeSecretKey(h, user.Email)
		user.TOTPSecretKey = secret
		h.bodyReader.Return = mocks.Values{Code: "wrong"}

		h.loadClientState(w, &r)

		if err := h.totp.PostRemove(w, r); err != nil {
			t.Error(err)
		}

		if h.responder.Page != PageTOTPRemove {
			t.Error("page wrong:", h.responder.Page)
		}
		if got := h.responder.Data[authboss.DataValidation].(map[string][]string); got[FormValueCode][0] != h.ab.Localizef(context.Background(), authboss.TxtInvalid2FACode) {
			t.Error("data wrong:", got)
		}
	})

	t.Run("OkCode", func(t *testing.T) {
		h := testSetup()

		r, w, _ := h.newHTTP("POST")

		user := setupMore(h)
		secret := makeSecretKey(h, user.Email)
		user.TOTPSecretKey = secret
		h.setSession(authboss.Session2FA, "totp")
		h.loadClientState(w, &r)

		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		h.bodyReader.Return = mocks.Values{Code: code}

		if err := h.totp.PostRemove(w, r); err != nil {
			t.Error(err)
		}

		if h.responder.Page != PageTOTPRemoveSuccess {
			t.Error("page wrong:", h.responder.Page)
		}

		// Flush client state
		w.WriteHeader(http.StatusOK)

		if _, ok := h.session.ClientValues[authboss.Session2FA]; ok {
			t.Error("session 2fa should be cleared")
		}
	})
}

func TestGetValidate(t *testing.T) {
	t.Parallel()
	h := testSetup()

	r, w, _ := h.newHTTP("GET")

	if err := h.totp.GetValidate(w, r); err != nil {
		t.Error(err)
	}

	if h.responder.Page != PageTOTPValidate {
		t.Error("page wrong:", h.responder.Page)
	}
}

func TestPostValidate(t *testing.T) {
	t.Parallel()

	setupMore := func(h *testHarness) *mocks.User {
		user := &mocks.User{Email: "test@test.com"}
		h.storer.Users[user.Email] = user
		h.setSession(authboss.SessionKey, user.Email)
		h.session.ClientValues[authboss.SessionKey] = user.Email

		return user
	}

	t.Run("NoTOTPActivated", func(t *testing.T) {
		h := testSetup()

		r, w, _ := h.newHTTP("POST")

		setupMore(h)
		h.loadClientState(w, &r)

		// No session
		if err := h.totp.PostValidate(w, r); err != nil {
			t.Fatal(err)
		}

		if h.responder.Page != PageTOTPValidate {
			t.Error("page wrong:", h.responder.Page)
		}
		if got := h.responder.Data[authboss.DataErr]; got != h.ab.Localizef(context.Background(), authboss.TxtTOTP2FANotActive) {
			t.Error("data wrong:", got)
		}
	})

	t.Run("WrongCode", func(t *testing.T) {
		h := testSetup()

		r, w, _ := h.newHTTP("POST")
		h.loadClientState(w, &r)

		user := setupMore(h)
		secret := makeSecretKey(h, user.Email)
		user.TOTPSecretKey = secret
		h.bodyReader.Return = mocks.Values{Code: "wrong"}

		if err := h.totp.PostValidate(w, r); err != nil {
			t.Error(err)
		}

		if h.responder.Page != PageTOTPValidate {
			t.Error("page wrong:", h.responder.Page)
		}
		if got := h.responder.Data[authboss.DataValidation].(map[string][]string); got[FormValueCode][0] != h.ab.Localizef(context.Background(), authboss.TxtInvalid2FACode) {
			t.Error("data wrong:", got)
		}
	})

	t.Run("ReusedCode", func(t *testing.T) {
		h := testSetup()

		r, w, _ := h.newHTTP("POST")
		h.loadClientState(w, &r)

		user := setupMore(h)
		secret := makeSecretKey(h, user.Email)
		user.TOTPSecretKey = secret
		user.TOTPLastCode = "duplicate"
		h.bodyReader.Return = mocks.Values{Code: "duplicate"}

		if err := h.totp.PostValidate(w, r); err != nil {
			t.Error(err)
		}

		if h.responder.Page != PageTOTPValidate {
			t.Error("page wrong:", h.responder.Page)
		}
		if got := h.responder.Data[authboss.DataValidation].(map[string][]string); got[FormValueCode][0] != h.ab.Localizef(context.Background(), authboss.TxtRepeated2FACode) {
			t.Error("data wrong:", got)
		}
	})

	t.Run("OkRecovery", func(t *testing.T) {
		h := testSetup()

		r, w, _ := h.newHTTP("POST")
		user := setupMore(h)
		secret := makeSecretKey(h, user.Email)
		user.TOTPSecretKey = secret

		// Create a single recovery code
		codes, err := twofactor.GenerateRecoveryCodes()
		if err != nil {
			t.Fatal(err)
		}
		b, err := bcrypt.GenerateFromPassword([]byte(codes[0]), bcrypt.DefaultCost)
		if err != nil {
			t.Fatal(err)
		}
		user.RecoveryCodes = string(b)

		// User inputs the only code he has
		h.bodyReader.Return = mocks.Values{Recovery: codes[0]}

		h.setSession(SessionTOTPPendingPID, user.Email)
		h.setSession(SessionTOTPSecret, "secret")
		h.setSession(authboss.SessionHalfAuthKey, "true")
		h.loadClientState(w, &r)

		if err := h.totp.PostValidate(w, r); err != nil {
			t.Error(err)
		}

		// Flush client state
		w.WriteHeader(http.StatusOK)

		if pid := h.session.ClientValues[authboss.SessionKey]; pid != user.Email {
			t.Error("session pid should be set:", pid)
		}
		if twofa := h.session.ClientValues[authboss.Session2FA]; twofa != "totp" {
			t.Error("session 2fa should be totp:", twofa)
		}

		cleared := []string{SessionTOTPSecret, SessionTOTPPendingPID, authboss.SessionHalfAuthKey}
		for _, c := range cleared {
			if _, ok := h.session.ClientValues[c]; ok {
				t.Error(c, "was not cleared")
			}
		}

		opts := h.redirector.Options
		if opts.Code != http.StatusTemporaryRedirect {
			t.Error("status wrong:", opts.Code)
		}
		if !opts.FollowRedirParam {
			t.Error("it should follow redirects")
		}
		if opts.RedirectPath != h.ab.Paths.AuthLoginOK {
			t.Error("path wrong:", opts.RedirectPath)
		}
	})

	t.Run("InvalidRecovery", func(t *testing.T) {
		h := testSetup()

		r, w, _ := h.newHTTP("POST")
		user := setupMore(h)
		secret := makeSecretKey(h, user.Email)
		user.TOTPSecretKey = secret

		// User inputs invalid recovery code
		h.bodyReader.Return = mocks.Values{Recovery: "INVALID"}

		h.setSession(SessionTOTPPendingPID, user.Email)
		h.setSession(SessionTOTPSecret, "secret")
		h.setSession(authboss.SessionHalfAuthKey, "true")
		h.loadClientState(w, &r)

		if err := h.totp.PostValidate(w, r); err != nil {
			t.Error(err)
		}

		// Flush client state
		w.WriteHeader(http.StatusOK)

		if got := h.responder.Data[authboss.DataValidation].(map[string][]string); got[FormValueCode][0] != h.ab.Localizef(context.Background(), authboss.TxtInvalid2FACode) {
			t.Error("data wrong:", got)
		}
	})
}

func makeSecretKey(h *testHarness, email string) string {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      h.totp.Modules.TOTP2FAIssuer,
		AccountName: email,
	})
	if err != nil {
		panic(err)
	}

	return key.Secret()
}
