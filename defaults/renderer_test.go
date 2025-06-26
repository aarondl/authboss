package defaults

import (
	"context"
	"testing"

	"github.com/aarondl/authboss/v3"
)

func TestJSONRenderer(t *testing.T) {
	t.Parallel()

	r := JSONRenderer{}

	success := authboss.HTMLData{"fun": "times"}
	failure := authboss.HTMLData{authboss.DataErr: "problem"}
	hasAlready := authboss.HTMLData{authboss.DataErr: "problem", "status": "noproblem"}

	b, _, err := r.Render(context.Background(), "", success)
	if err != nil {
		t.Error(err)
	}
	if string(b) != `{"fun":"times","status":"success"}` {
		t.Errorf("wrong json: %s", b)
	}

	b, _, err = r.Render(context.Background(), "", failure)
	if err != nil {
		t.Error(err)
	}
	if string(b) != `{"error":"problem","status":"failure"}` {
		t.Errorf("wrong json: %s", b)
	}

	b, _, err = r.Render(context.Background(), "", hasAlready)
	if err != nil {
		t.Error(err)
	}
	if string(b) != `{"error":"problem","status":"noproblem"}` {
		t.Errorf("wrong json: %s", b)
	}
}
