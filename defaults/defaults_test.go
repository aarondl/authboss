package defaults

import (
	"testing"

	"github.com/aarondl/authboss/v3"
)

func TestSetCore(t *testing.T) {
	t.Parallel()

	config := &authboss.Config{}
	SetCore(config, false, false)

	if config.Core.Logger == nil {
		t.Error("logger should be set")
	}
	if config.Core.Router == nil {
		t.Error("router should be set")
	}
	if config.Core.ErrorHandler == nil {
		t.Error("error handler should be set")
	}
	if config.Core.Responder == nil {
		t.Error("responder should be set")
	}
	if config.Core.Redirector == nil {
		t.Error("redirector should be set")
	}
	if config.Core.BodyReader == nil {
		t.Error("bodyreader should be set")
	}
	if config.Core.Mailer == nil {
		t.Error("mailer should be set")
	}
	if config.Core.Logger == nil {
		t.Error("logger should be set")
	}
}
