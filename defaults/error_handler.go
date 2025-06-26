package defaults

import (
	"fmt"
	"net/http"

	"github.com/aarondl/authboss/v3"
)

// ErrorHandler wraps http handlers with errors with itself
// to provide error handling.
//
// The pieces provided to this struct must be thread-safe
// since they will be handed to many pointers to themselves.
type ErrorHandler struct {
	LogWriter authboss.Logger
}

// NewErrorHandler constructor
func NewErrorHandler(logger authboss.Logger) ErrorHandler {
	return ErrorHandler{LogWriter: logger}
}

// Wrap an http handler with an error
func (e ErrorHandler) Wrap(handler func(w http.ResponseWriter, r *http.Request) error) http.Handler {
	return errorHandler{
		Handler:   handler,
		LogWriter: e.LogWriter,
	}
}

type errorHandler struct {
	Handler   func(w http.ResponseWriter, r *http.Request) error
	LogWriter authboss.Logger
}

// ServeHTTP handles errors
func (e errorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := e.Handler(w, r)
	if err == nil {
		return
	}

	e.LogWriter.Error(fmt.Sprintf("request error from (%s) %s: %+v", r.RemoteAddr, r.URL.String(), err))
}
