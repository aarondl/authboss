package recover

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aarondl/authboss/v3"
	"github.com/aarondl/authboss/v3/mocks"
)

func testSetupWithSecondaryEmails() *testHarness {
	harness := &testHarness{}

	harness.ab = authboss.New()
	harness.bodyReader = &mocks.BodyReader{}
	harness.mailer = &mocks.Emailer{}
	harness.redirector = &mocks.Redirector{}
	harness.renderer = &mocks.Renderer{}
	harness.responder = &mocks.Responder{}
	harness.session = mocks.NewClientRW()
	harness.storer = mocks.NewServerStorer()

	harness.ab.Paths.RecoverOK = "/recover/ok"
	harness.ab.Modules.MailNoGoroutine = true

	harness.ab.Config.Core.BodyReader = harness.bodyReader
	harness.ab.Config.Core.Logger = mocks.Logger{}
	harness.ab.Config.Core.Hasher = mocks.Hasher{}
	harness.ab.Config.Core.Mailer = harness.mailer
	harness.ab.Config.Core.Redirector = harness.redirector
	harness.ab.Config.Core.MailRenderer = harness.renderer
	harness.ab.Config.Core.Responder = harness.responder
	harness.ab.Config.Storage.SessionState = harness.session
	harness.ab.Config.Storage.Server = mocks.ServerStorerWithSecondaryEmails{
		BasicStorer: harness.storer,
	}

	harness.recover = &Recover{harness.ab}

	return harness
}

func TestSecondaryEmails(t *testing.T) {
	t.Parallel()

	h := testSetupWithSecondaryEmails()

	h.bodyReader.Return = &mocks.Values{
		PID: "test@test.com",
	}
	h.storer.Users["test@test.com"] = &mocks.User{
		Email:    "test@test.com",
		Password: "i can't recall, doesn't seem like something bcrypted though",
	}

	r := mocks.Request("GET")
	w := httptest.NewRecorder()

	if err := h.recover.StartPost(w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("code was wrong:", w.Code)
	}
	if h.redirector.Options.RedirectPath != h.ab.Config.Paths.RecoverOK {
		t.Error("page was wrong:", h.responder.Page)
	}
	if len(h.redirector.Options.Success) == 0 {
		t.Error("expected a nice success message")
	}

	if h.mailer.Email.To[0] != "test@test.com" {
		t.Error("e-mail to address is wrong:", h.mailer.Email.To)
	}
	if !strings.HasSuffix(h.mailer.Email.Subject, "Password Reset") {
		t.Error("e-mail subject line is wrong:", h.mailer.Email.Subject)
	}
	if len(h.renderer.Data[DataRecoverURL].(string)) == 0 {
		t.Errorf("the renderer's url in data was missing: %#v", h.renderer.Data)
	}

	if len(h.mailer.Email.To) != 3 {
		t.Errorf("should have sent 3 e-mails out, but sent %d", len(h.mailer.Email.To))
	}
}
