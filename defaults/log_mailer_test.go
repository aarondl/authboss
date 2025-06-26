package defaults

import (
	"bytes"
	"context"
	"math/rand"
	"strings"
	"testing"

	"github.com/aarondl/authboss/v3"
)

func TestMailer(t *testing.T) {
	t.Parallel()

	mailServer := &bytes.Buffer{}
	mailer := NewLogMailer(mailServer)

	err := mailer.Send(context.Background(), authboss.Email{
		To:       []string{"some@email.com", "a@a.com"},
		ToNames:  []string{"Jake", "Noname"},
		From:     "some@guy.com",
		FromName: "Joseph",
		ReplyTo:  "an@email.com",
		Subject:  "Email!",
		TextBody: "No html here",
		HTMLBody: "<html>body</html>",
	})
	if err != nil {
		t.Error(err)
	}

	if mailServer.Len() == 0 {
		t.Error("It should have logged the e-mail.")
	}

	str := mailServer.String()
	if !strings.Contains(str, "From: Joseph <some@guy.com>") {
		t.Error("From line not present.")
	}

	if !strings.Contains(str, "To: Jake <some@email.com>, Noname <a@a.com>") {
		t.Error("To line not present.")
	}

	if !strings.Contains(str, "No html here") {
		t.Error("Text body not present.")
	}

	if !strings.Contains(str, "<html>body</html>") {
		t.Error("Html body not present.")
	}

	if t.Failed() {
		t.Log(str)
	}
}

func TestBoundary(t *testing.T) {
	t.Parallel()

	mailer := &SMTPMailer{"server", nil, rand.New(rand.NewSource(3))}
	if got := mailer.boundary(); got != "fe3fhpsm69lx8jvnrnju0wr" {
		t.Error("boundary was wrong", got)
	}
}
