package defaults

import (
	"net/http"
	"strings"

	"github.com/aarondl/authboss/v3"
)

// Responder helps respond to http requests
type Responder struct {
	Renderer authboss.Renderer
}

// NewResponder constructor
func NewResponder(renderer authboss.Renderer) *Responder {
	return &Responder{Renderer: renderer}
}

// Respond to an HTTP request. Its main job is to merge data that comes in from
// various middlewares via the context with the data sent by the controller and
// render that.
func (r *Responder) Respond(w http.ResponseWriter, req *http.Request, code int, page string, data authboss.HTMLData) error {
	ctxData := req.Context().Value(authboss.CTXKeyData)
	if ctxData != nil {
		if data == nil {
			data = authboss.HTMLData{}
		}
		data.Merge(ctxData.(authboss.HTMLData))
	}

	rendered, mime, err := r.Renderer.Render(req.Context(), page, data)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", mime)
	w.WriteHeader(code)

	_, err = w.Write(rendered)
	return err
}

func isAPIRequest(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")
}

// Redirector for http requests
type Redirector struct {
	Renderer authboss.Renderer

	// FormValueName for the redirection
	FormValueName string

	// CoerceRedirectTo200 forces http.StatusTemporaryRedirect and
	// and http.StatusPermanentRedirect to http.StatusOK
	CorceRedirectTo200 bool
}

// NewRedirector constructor
func NewRedirector(renderer authboss.Renderer, formValueName string) *Redirector {
	return &Redirector{FormValueName: formValueName, Renderer: renderer}
}

// Redirect the client elsewhere. If it's an API request it will simply render
// a JSON response with information that should help a client to decide what
// to do.
func (r *Redirector) Redirect(w http.ResponseWriter, req *http.Request, ro authboss.RedirectOptions) error {
	var redirectFunction = r.redirectNonAPI
	if isAPIRequest(req) {
		redirectFunction = r.redirectAPI
	}

	return redirectFunction(w, req, ro)
}

func (r Redirector) redirectAPI(w http.ResponseWriter, req *http.Request, ro authboss.RedirectOptions) error {
	path := ro.RedirectPath
	redir := req.FormValue(r.FormValueName)
	if strings.Contains(redir, "://") {
		// Guard against Open Redirect: https://cwe.mitre.org/data/definitions/601.html
		redir = ""
	}
	if len(redir) != 0 && ro.FollowRedirParam {
		path = redir
	}

	var status = "success"
	var message string
	if len(ro.Success) != 0 {
		message = ro.Success
	}
	if len(ro.Failure) != 0 {
		status = "failure"
		message = ro.Failure
	}

	data := authboss.HTMLData{
		"location": path,
	}

	data["status"] = status
	if len(message) != 0 {
		data["message"] = message
	}

	body, mime, err := r.Renderer.Render(req.Context(), "redirect", data)
	if err != nil {
		return err
	}

	if len(body) != 0 {
		w.Header().Set("Content-Type", mime)
	}

	if ro.Code != 0 {
		if r.CorceRedirectTo200 && (ro.Code == http.StatusTemporaryRedirect || ro.Code == http.StatusPermanentRedirect) {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(ro.Code)
		}
	}
	_, err = w.Write(body)
	return err
}

func (r Redirector) redirectNonAPI(w http.ResponseWriter, req *http.Request, ro authboss.RedirectOptions) error {
	path := ro.RedirectPath
	redir := req.FormValue(r.FormValueName)
	if strings.Contains(redir, "://") {
		// Guard against Open Redirect: https://cwe.mitre.org/data/definitions/601.html
		redir = ""
	}
	if len(redir) != 0 && ro.FollowRedirParam {
		path = redir
	}

	if len(ro.Success) != 0 {
		authboss.PutSession(w, authboss.FlashSuccessKey, ro.Success)
	}
	if len(ro.Failure) != 0 {
		authboss.PutSession(w, authboss.FlashErrorKey, ro.Failure)
	}

	http.Redirect(w, req, path, http.StatusFound)
	return nil
}
