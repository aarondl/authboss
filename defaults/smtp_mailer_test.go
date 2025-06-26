package defaults

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/smtp"
	"os"
	"testing"

	"github.com/aarondl/authboss/v3"
)

var (
	flagTestSMTPMailer = flag.Bool("test-smtp-mailer", false, "Test the smtp mailer")
)

func TestSMTPMailer(t *testing.T) {
	t.Parallel()

	if !*flagTestSMTPMailer {
		t.Skip("SMTP Mailer Testing not enabled (-test-smtp-mailer flag)")
	}

	creds := struct {
		Server   string `json:"server,omitempty"`
		Port     int    `json:"port,omitempty"`
		Email    string `json:"email,omitempty"`
		Password string `json:"password,omitempty"`
	}{}

	b, err := os.ReadFile("smtp_mailer_test.json")
	if err != nil {
		t.Fatal(`error reading file: "smtp_mailer_test.json`, err)
	}

	if err = json.Unmarshal(b, &creds); err != nil {
		t.Fatal(err)
	}

	server := fmt.Sprintf("%s:%d", creds.Server, creds.Port)
	mailer := NewSMTPMailer(server, smtp.PlainAuth("", creds.Email, creds.Password, creds.Server))

	mail := authboss.Email{
		From:    creds.Email,
		To:      []string{creds.Email},
		Subject: "Authboss Test SMTP Mailer",
	}

	txtOnly := mail
	txtOnly.Subject += ": Text Content"
	txtOnly.TextBody = "Authboss\nSMTP\nTest\nWith\nNewlines"

	if err = mailer.Send(context.Background(), txtOnly); err != nil {
		t.Error(err)
	}

	htmlOnly := mail
	htmlOnly.Subject += ": HTML Content"
	htmlOnly.HTMLBody = "Authboss<br>Test<br>\nWith<br>Newlines\nand<br>breaks"

	if err = mailer.Send(context.Background(), htmlOnly); err != nil {
		t.Error(err)
	}

	mixed := mail
	mixed.Subject += ": Mixed Content"
	mixed.HTMLBody = htmlOnly.HTMLBody
	mixed.TextBody = txtOnly.TextBody

	if err = mailer.Send(context.Background(), mixed); err != nil {
		t.Error(err)
	}
}

func TestSMTPMailerPanic(t *testing.T) {
	t.Parallel()

	_ = NewSMTPMailer("server", nil)

	recovered := false
	defer func() {
		recovered = recover() != nil
	}()

	NewSMTPMailer("", nil)

	if !recovered {
		t.Error("Should have panicked.")
	}
}
