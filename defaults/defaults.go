// Package defaults houses default implementations for the very many
// interfaces that authboss has. It's a goal of the defaults package
// to provide the core where authboss implements the shell.
//
// It's simultaneously supposed to be possible to take as many or
// as few of these implementations as you desire, allowing you to
// reimplement where necessary, but reuse where possible.
package defaults

import (
	"os"

	"github.com/aarondl/authboss/v3"
)

// SetCore creates instances of all the default pieces
// with the exception of ViewRenderer which should be already set
// before calling this method.
func SetCore(config *authboss.Config, readJSON, useUsername bool) {
	logger := NewLogger(os.Stdout)

	config.Core.Router = NewRouter()
	config.Core.ErrorHandler = NewErrorHandler(logger)
	config.Core.Responder = NewResponder(config.Core.ViewRenderer)
	config.Core.Redirector = NewRedirector(config.Core.ViewRenderer, authboss.FormValueRedirect)
	config.Core.BodyReader = NewHTTPBodyReader(readJSON, useUsername)
	config.Core.Mailer = NewLogMailer(os.Stdout)
	config.Core.Logger = logger
}
