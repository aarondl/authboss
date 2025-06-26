package defaults

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/aarondl/authboss/v3"
	"github.com/aarondl/authboss/v3/mocks"
)

type testRenderer struct {
	Callback func(context.Context, string, authboss.HTMLData) ([]byte, string, error)
}

func (t testRenderer) Load(names ...string) error {
	return nil
}

func (t testRenderer) Render(ctx context.Context, name string, data authboss.HTMLData) ([]byte, string, error) {
	return t.Callback(ctx, name, data)
}

func testJSONRender(ctx context.Context, name string, data authboss.HTMLData) ([]byte, string, error) {
	b, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}

	return b, "application/json", nil
}

func TestResponder(t *testing.T) {
	t.Parallel()

	renderer := testRenderer{
		Callback: testJSONRender,
	}

	responder := Responder{
		Renderer: renderer,
	}

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	r = r.WithContext(context.WithValue(context.Background(), authboss.CTXKeyData, authboss.HTMLData{
		"csrfname":  "csrf",
		"csrftoken": "12345",
	}))

	err := responder.Respond(w, r, http.StatusCreated, "some_template.tpl", authboss.HTMLData{"auth_happy": true})
	if err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusCreated {
		t.Error("code was wrong:", w.Code)
	}

	if got := w.Result().Header.Get("Content-Type"); got != "application/json" {
		t.Error("content type was wrong:", got)
	}

	expectData := authboss.HTMLData{
		"csrfname":   "csrf",
		"csrftoken":  "12345",
		"auth_happy": true,
	}

	var gotData authboss.HTMLData
	if err := json.Unmarshal(w.Body.Bytes(), &gotData); err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(gotData, expectData) {
		t.Errorf("data mismatched:\nwant: %#v\ngot:  %#v", expectData, gotData)
	}
}

func TestRedirector(t *testing.T) {
	t.Parallel()

	renderer := testRenderer{
		Callback: testJSONRender,
	}

	redir := Redirector{
		FormValueName: "redir",
		Renderer:      renderer,
	}

	r := httptest.NewRequest("POST", "/?redir=/pow", nil)
	w := httptest.NewRecorder()

	r.Header.Set("Content-Type", "application/json")

	ro := authboss.RedirectOptions{
		Success:      "ok!",
		Code:         http.StatusTeapot,
		RedirectPath: "/redirect", FollowRedirParam: false,
	}

	if err := redir.Redirect(w, r, ro); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusTeapot {
		t.Error("code is wrong:", w.Code)
	}

	var gotData map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &gotData); err != nil {
		t.Fatal(err)
	}

	if got := gotData["status"]; got != "success" {
		t.Error("status was wrong:", got)
	}
	if got := gotData["message"]; got != "ok!" {
		t.Error("message was wrong:", got)
	}
	if got := gotData["location"]; got != "/redirect" {
		t.Error("location was wrong:", got)
	}
}

func TestResponseRedirectAPIFollowRedir(t *testing.T) {
	t.Parallel()

	renderer := testRenderer{
		Callback: testJSONRender,
	}

	redir := Redirector{
		FormValueName: "redir",
		Renderer:      renderer,
	}

	r := httptest.NewRequest("POST", "/?redir=/pow", nil)
	w := httptest.NewRecorder()

	r.Header.Set("Content-Type", "application/json")

	ro := authboss.RedirectOptions{
		Failure:      ":(",
		Code:         http.StatusTeapot,
		RedirectPath: "/redirect", FollowRedirParam: true,
	}

	if err := redir.Redirect(w, r, ro); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusTeapot {
		t.Error("code is wrong:", w.Code)
	}

	var gotData map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &gotData); err != nil {
		t.Fatal(err)
	}

	if got := gotData["status"]; got != "failure" {
		t.Error("status was wrong:", got)
	}
	if got := gotData["message"]; got != ":(" {
		t.Error("message was wrong:", got)
	}
	if got := gotData["location"]; got != "/pow" {
		t.Error("location was wrong:", got)
	}
}

func TestResponseRedirectNonAPI(t *testing.T) {
	t.Parallel()

	renderer := testRenderer{
		Callback: func(ctx context.Context, name string, data authboss.HTMLData) ([]byte, string, error) {
			return nil, "", nil
		},
	}

	redir := Redirector{
		FormValueName: "redir",
		Renderer:      renderer,
	}

	r := httptest.NewRequest("POST", "/?redir=/pow", nil)
	w := httptest.NewRecorder()

	ab := authboss.New()
	ab.Config.Storage.SessionState = mocks.NewClientRW()
	ab.Config.Storage.CookieState = mocks.NewClientRW()
	aw := ab.NewResponse(w)

	ro := authboss.RedirectOptions{
		Success: "success", Failure: "failure",
		RedirectPath: "/redirect", FollowRedirParam: false,
	}

	if err := redir.Redirect(aw, r, ro); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusFound {
		t.Error("code is wrong:", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/redirect" {
		t.Error("redirect location was wrong:", got)
	}
}

func TestResponseRedirectNonAPIFollowRedir(t *testing.T) {
	t.Parallel()

	renderer := testRenderer{
		Callback: func(ctx context.Context, name string, data authboss.HTMLData) ([]byte, string, error) {
			return nil, "", nil
		},
	}

	redir := Redirector{
		FormValueName: "redir",
		Renderer:      renderer,
	}

	r := httptest.NewRequest("POST", "/?redir=/pow", nil)
	w := httptest.NewRecorder()

	ab := authboss.New()
	ab.Config.Storage.SessionState = mocks.NewClientRW()
	ab.Config.Storage.CookieState = mocks.NewClientRW()
	aw := ab.NewResponse(w)

	ro := authboss.RedirectOptions{
		RedirectPath: "/redirect", FollowRedirParam: true,
	}
	if err := redir.Redirect(aw, r, ro); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusFound {
		t.Error("code is wrong:", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/pow" {
		t.Error("redirect location was wrong:", got)
	}
}
