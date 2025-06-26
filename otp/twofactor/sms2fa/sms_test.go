package sms2fa

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aarondl/authboss/v3/otp/twofactor"
	"golang.org/x/crypto/bcrypt"

	"github.com/aarondl/authboss/v3"
	"github.com/aarondl/authboss/v3/mocks"
)

type smsHolderSender string

func (s *smsHolderSender) Send(ctx context.Context, number, text string) error {
	*s = smsHolderSender(text)
	return nil
}

func TestSMSSetup(t *testing.T) {
	t.Parallel()

	ab := authboss.New()
	router := &mocks.Router{}
	renderer := &mocks.Renderer{}
	errHandler := &mocks.ErrorHandler{}

	ab.Config.Core.Router = router
	ab.Config.Core.ViewRenderer = renderer
	ab.Config.Core.ErrorHandler = errHandler

	sms := &SMS{Authboss: ab, Sender: new(smsHolderSender)}
	if err := sms.Setup(); err != nil {
		t.Fatal(err)
	}

	gets := []string{"/2fa/sms/setup", "/2fa/sms/confirm", "/2fa/sms/remove", "/2fa/sms/validate"}
	posts := []string{"/2fa/sms/setup", "/2fa/sms/confirm", "/2fa/sms/remove", "/2fa/sms/validate"}
	if err := router.HasGets(gets...); err != nil {
		t.Error(err)
	}
	if err := router.HasPosts(posts...); err != nil {
		t.Error(err)
	}
}

type testHarness struct {
	sms    *SMS
	ab     *authboss.Authboss
	sender *smsHolderSender

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

	harness.sender = new(smsHolderSender)
	harness.sms = &SMS{Authboss: harness.ab, Sender: harness.sender}

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

		handled, err := harness.sms.HijackAuth(nil, nil, true)
		if handled {
			t.Error("should not be handled")
		}
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("UserNoSMS", func(t *testing.T) {
		harness := testSetup()

		r, w, _ := harness.newHTTP("POST")
		r.URL.RawQuery = "test=query"

		user := &mocks.User{Email: "test@test.com"}
		harness.putUserInCtx(user, &r)

		harness.loadClientState(w, &r)
		handled, err := harness.sms.HijackAuth(w, r, false)
		if handled {
			t.Error("should not be handled")
		}
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("Ok", func(t *testing.T) {
		harness := testSetup()

		handled, err := harness.sms.HijackAuth(nil, nil, true)
		if handled {
			t.Error("should not be handled")
		}
		if err != nil {
			t.Error(err)
		}

		r, w, _ := harness.newHTTP("POST")
		r.URL.RawQuery = "test=query"

		user := &mocks.User{Email: "test@test.com", SMSPhoneNumber: "number"}
		harness.putUserInCtx(user, &r)
		harness.loadClientState(w, &r)

		handled, err = harness.sms.HijackAuth(w, r, false)
		if !handled {
			t.Error("should be handled")
		}
		if err != nil {
			t.Error(err)
		}

		if len(*harness.sender) == 0 {
			t.Error("a code should have been sent via sms")
		}

		if _, ok := harness.session.ClientValues[SessionSMSLast]; !ok {
			t.Error("it should record the time it was last sent at")
		}
		if _, ok := harness.session.ClientValues[SessionSMSSecret]; !ok {
			t.Error("there should be a code")
		}

		opts := harness.redirector.Options
		if opts.Code != http.StatusTemporaryRedirect {
			t.Error("status wrong:", opts.Code)
		}

		if opts.RedirectPath != "/auth/2fa/sms/validate?test=query" {
			t.Error("redir path wrong:", opts.RedirectPath)
		}
	})
}

func TestSendCodeSuppression(t *testing.T) {
	t.Parallel()

	h := testSetup()
	r, w, _ := h.newHTTP("POST")

	if err := h.sms.SendCodeToUser(w, r, "pid", "phonenumber"); err != nil {
		t.Error(err)
	}

	// Flush the session sets, reload the client state
	w.WriteHeader(http.StatusOK)
	h.loadClientState(w, &r)

	// Send again within 10s, hopefully Go can execute that fast :D
	if err := h.sms.SendCodeToUser(w, r, "pid", "phonenumber"); err == nil {
		t.Error("should have errored")
	} else if err != errSMSRateLimit {
		t.Error("it should have blocked the second send")
	}
}

func TestGetSetup(t *testing.T) {
	t.Parallel()

	h := testSetup()
	r, w, _ := h.newHTTP("GET")

	user := &mocks.User{Email: "test@test.com", SMSPhoneNumberSeed: "seednumber"}
	h.storer.Users[user.Email] = user

	h.setSession(authboss.SessionKey, user.Email)
	h.setSession(SessionSMSSecret, "secret")
	h.setSession(SessionSMSNumber, "number")
	h.loadClientState(w, &r)

	if err := h.sms.GetSetup(w, r); err != nil {
		t.Error(err)
	}

	// Flush ClientState
	w.WriteHeader(http.StatusOK)

	if h.session.ClientValues[SessionSMSSecret] != "" {
		t.Error("session sms secret should be cleared")
	}
	if h.session.ClientValues[SessionSMSNumber] != "" {
		t.Error("session sms number should be cleared")
	}

	if h.responder.Page != PageSMSSetup {
		t.Error("page wrong:", h.responder.Page)
	}
	if got := h.responder.Data[DataSMSPhoneNumber]; got != "seednumber" {
		t.Error("data wrong:", got)
	}
}

func TestPostSetup(t *testing.T) {
	t.Parallel()

	t.Run("NoPhoneNumber", func(t *testing.T) {
		h := testSetup()
		r, w, _ := h.newHTTP("POST")

		user := &mocks.User{Email: "test@test.com"}
		h.storer.Users[user.Email] = user
		h.setSession(authboss.SessionKey, user.Email)
		h.loadClientState(w, &r)

		h.bodyReader.Return = mocks.Values{PhoneNumber: ""}

		if err := h.sms.PostSetup(w, r); err != nil {
			t.Error(err)
		}

		if h.responder.Page != PageSMSSetup {
			t.Error("page wrong:", h.responder.Page)
		}
		validation := h.responder.Data[authboss.DataValidation].(map[string][]string)
		if got := validation[FormValuePhoneNumber][0]; got != h.ab.Localizef(context.Background(), authboss.TxtSMSNumberRequired) {
			t.Error("data wrong:", got)
		}
	})

	t.Run("Ok", func(t *testing.T) {
		h := testSetup()
		r, w, _ := h.newHTTP("POST")

		user := &mocks.User{Email: "test@test.com"}
		h.storer.Users[user.Email] = user
		h.setSession(authboss.SessionKey, user.Email)
		h.loadClientState(w, &r)

		h.bodyReader.Return = mocks.Values{PhoneNumber: "number"}

		if err := h.sms.PostSetup(w, r); err != nil {
			t.Error(err)
		}

		// Flush ClientState
		w.WriteHeader(http.StatusOK)

		if val := h.session.ClientValues[SessionSMSNumber]; val != "number" {
			t.Error("session value wrong:", val)
		}
		if val := h.session.ClientValues[SessionSMSLast]; len(val) == 0 {
			t.Error("session sms last should be set by send")
		}

		code := string(*h.sender)
		if val := h.session.ClientValues[SessionSMSSecret]; val != code {
			t.Error("the code should be stored in the session")
		}

		opts := h.redirector.Options
		if opts.Code != http.StatusTemporaryRedirect {
			t.Error("code was wrong:", opts.Code)
		}
		if opts.RedirectPath != "/auth/2fa/sms/confirm" {
			t.Error("redirect path was wrong:", opts.RedirectPath)
		}
	})
}

func TestValidatorGet(t *testing.T) {
	t.Parallel()

	h := testSetup()
	validator := &SMSValidator{SMS: h.sms, Page: PageSMSConfirm}

	r, w, _ := h.newHTTP("GET")
	if err := validator.Get(w, r); err != nil {
		t.Fatal(err)
	}

	if h.responder.Page != PageSMSConfirm {
		t.Error("page wrong:", h.responder.Page)
	}
}

func TestValidatorPostSend(t *testing.T) {
	t.Parallel()

	h := testSetup()
	validator := &SMSValidator{SMS: h.sms, Page: PageSMSValidate}

	r, w, _ := h.newHTTP("POST")

	user := &mocks.User{Email: "test@test.com", SMSPhoneNumber: "number"}
	h.storer.Users[user.Email] = user
	h.setSession(authboss.SessionKey, user.Email)
	h.loadClientState(w, &r)
	h.bodyReader.Return = mocks.Values{}

	if err := validator.Post(w, r); err != nil {
		t.Fatal(err)
	}

	if code := string(*h.sender); len(code) == 0 {
		t.Error("should have sent a code")
	}

	*h.sender = ""

	// When action is confirm, it retrieves the phone number from
	// the session, not the user.
	validator.Page = PageSMSConfirm
	user.SMSPhoneNumber = ""
	h.setSession(SessionSMSNumber, "number")
	h.loadClientState(w, &r)

	if err := validator.Post(w, r); err != nil {
		t.Fatal(err)
	}

	if code := string(*h.sender); len(code) == 0 {
		t.Error("should have sent a code")
	}
}

func TestValidatorPostOk(t *testing.T) {
	t.Parallel()

	t.Run("OkConfirm", func(t *testing.T) {
		h := testSetup()
		r, w, _ := h.newHTTP("POST")
		v := &SMSValidator{SMS: h.sms, Page: PageSMSConfirm}

		user := &mocks.User{Email: "test@test.com"}
		h.storer.Users[user.Email] = user
		h.setSession(authboss.SessionKey, user.Email)

		code := "code"
		h.setSession(SessionSMSSecret, code)
		h.setSession(SessionSMSNumber, "number")
		h.bodyReader.Return = mocks.Values{Code: code}

		h.loadClientState(w, &r)

		if err := v.Post(w, r); err != nil {
			t.Fatal(err)
		}

		// Flush client state
		w.WriteHeader(http.StatusOK)

		if h.responder.Page != PageSMSConfirmSuccess {
			t.Error("page wrong:", h.responder.Page)
		}
		if got := h.responder.Data[twofactor.DataRecoveryCodes].([]string); len(got) == 0 {
			t.Error("recovery codes should have been returned")
		}

		if h.session.ClientValues[SessionSMSNumber] != "" {
			t.Error("session sms number should be cleared")
		}
		if h.session.ClientValues[SessionSMSSecret] != "" {
			t.Error("session sms secret should be cleared")
		}

		if got := user.GetSMSPhoneNumber(); got != "number" {
			t.Error("sms phone number was wrong:", got)
		}
		if len(user.GetRecoveryCodes()) == 0 {
			t.Error("recovery codes should have been saved")
		}
	})

	t.Run("OkRemoveWithRecovery", func(t *testing.T) {
		h := testSetup()
		r, w, _ := h.newHTTP("POST")
		v := &SMSValidator{SMS: h.sms, Page: PageSMSRemove}

		user := &mocks.User{Email: "test@test.com", SMSPhoneNumber: "number"}
		h.storer.Users[user.Email] = user
		h.setSession(authboss.SessionKey, user.Email)

		codes, err := twofactor.GenerateRecoveryCodes()
		if err != nil {
			t.Fatal(err)
		}
		b, err := bcrypt.GenerateFromPassword([]byte(codes[0]), bcrypt.DefaultCost)
		if err != nil {
			t.Fatal(err)
		}
		user.RecoveryCodes = string(b)

		h.setSession(SessionSMSSecret, "code-user-never-got")
		h.bodyReader.Return = mocks.Values{Recovery: codes[0]}

		h.loadClientState(w, &r)

		if err := v.Post(w, r); err != nil {
			t.Fatal(err)
		}

		// Flush client state
		w.WriteHeader(http.StatusOK)

		if h.responder.Page != PageSMSRemoveSuccess {
			t.Error("page wrong:", h.responder.Page)
		}

		if h.session.ClientValues[authboss.Session2FA] != "" {
			t.Error("session 2fa should be cleared")
		}

		if len(user.GetSMSPhoneNumber()) != 0 {
			t.Error("sms phone number should be cleared")
		}
		if len(user.GetRecoveryCodes()) != 0 {
			t.Error("last recovery code should have been used")
		}
	})

	t.Run("OkValidateWithCode", func(t *testing.T) {
		h := testSetup()
		r, w, _ := h.newHTTP("POST")
		v := &SMSValidator{SMS: h.sms, Page: PageSMSValidate}

		user := &mocks.User{Email: "test@test.com", SMSPhoneNumber: "number"}
		h.storer.Users[user.Email] = user
		h.setSession(authboss.SessionKey, user.Email)

		codes, err := twofactor.GenerateRecoveryCodes()
		if err != nil {
			t.Fatal(err)
		}
		b, err := bcrypt.GenerateFromPassword([]byte(codes[0]), bcrypt.DefaultCost)
		if err != nil {
			t.Fatal(err)
		}
		user.RecoveryCodes = string(b)

		h.setSession(SessionSMSSecret, "code-user-never-got")
		h.bodyReader.Return = mocks.Values{Recovery: codes[0]}

		h.loadClientState(w, &r)

		if err := v.Post(w, r); err != nil {
			t.Fatal(err)
		}

		// Flush client state
		w.WriteHeader(http.StatusOK)

		opts := h.redirector.Options
		if opts.Code != http.StatusTemporaryRedirect {
			t.Error("code was wrong:", opts.Code)
		}
		if opts.RedirectPath != v.Paths.AuthLoginOK {
			t.Error("path was wrong:", opts.RedirectPath)
		}
		if !opts.FollowRedirParam {
			t.Error("redir param is not set")
		}

		if pid := h.session.ClientValues[authboss.SessionKey]; pid != user.Email {
			t.Error("session pid should be set:", pid)
		}
		if twofa := h.session.ClientValues[authboss.Session2FA]; twofa != "sms" {
			t.Error("session 2fa should be sms:", twofa)
		}

		cleared := []string{SessionSMSSecret, SessionSMSPendingPID, authboss.SessionHalfAuthKey}
		for _, c := range cleared {
			if _, ok := h.session.ClientValues[c]; ok {
				t.Error(c, "was not cleared")
			}
		}
	})

	t.Run("InvalidRecovery", func(t *testing.T) {
		h := testSetup()
		r, w, _ := h.newHTTP("POST")
		v := &SMSValidator{SMS: h.sms, Page: PageSMSValidate}

		user := &mocks.User{Email: "test@test.com", SMSPhoneNumber: "number"}
		h.storer.Users[user.Email] = user
		h.setSession(authboss.SessionKey, user.Email)

		h.setSession(SessionSMSSecret, "code-user-never-got")
		h.bodyReader.Return = mocks.Values{Recovery: "INVALID"}

		h.loadClientState(w, &r)

		if err := v.Post(w, r); err != nil {
			t.Fatal(err)
		}

		// Flush client state
		w.WriteHeader(http.StatusOK)

		validation := h.responder.Data[authboss.DataValidation].(map[string][]string)
		if got := validation[FormValueCode][0]; got != h.ab.Localizef(context.Background(), authboss.TxtInvalid2FACode) {
			t.Error("data wrong:", got)
		}
	})

	t.Run("FailRemoveCode", func(t *testing.T) {
		h := testSetup()
		r, w, _ := h.newHTTP("POST")
		v := &SMSValidator{SMS: h.sms, Page: PageSMSRemove}

		user := &mocks.User{Email: "test@test.com"}
		h.storer.Users[user.Email] = user
		h.setSession(authboss.SessionKey, user.Email)

		h.setSession(SessionSMSSecret, "code")
		h.bodyReader.Return = mocks.Values{Code: "badcode"}

		h.loadClientState(w, &r)

		if err := v.Post(w, r); err != nil {
			t.Fatal(err)
		}

		if h.responder.Page != PageSMSRemove {
			t.Error("page wrong:", h.responder.Page)
		}
		validation := h.responder.Data[authboss.DataValidation].(map[string][]string)
		if got := validation[FormValueCode][0]; got != h.ab.Localizef(context.Background(), authboss.TxtInvalid2FACode) {
			t.Error("data wrong:", got)
		}
	})
}
