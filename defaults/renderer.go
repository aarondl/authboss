package defaults

import (
	"context"
	"encoding/json"

	"github.com/aarondl/authboss/v3"
)

var (
	jsonDefaultFailures = []string{authboss.DataErr, authboss.DataValidation}
)

// There is a separate package that does HTML Rendering authboss-renderer

// JSONRenderer simply renders the data provided in JSON.
// Known failure keys in the HTMLData can be passed in to force a
// status: failure in the JSON when they appear.
type JSONRenderer struct {
	Failures []string
}

// Load is a no-op since json doesn't require any templates
func (JSONRenderer) Load(names ...string) error {
	return nil
}

// Render the data
func (j JSONRenderer) Render(ctx context.Context, page string, data authboss.HTMLData) (output []byte, contentType string, err error) {
	if data == nil {
		return []byte(`{"status":"success"}`), "application/json", nil
	}

	if _, hasStatus := data["status"]; !hasStatus {
		failures := j.Failures
		if len(failures) == 0 {
			failures = jsonDefaultFailures
		}

		status := "success"
		for _, failure := range failures {
			val, has := data[failure]
			if has && val != nil {
				status = "failure"
				break
			}
		}

		data["status"] = status
	}

	b, err := json.Marshal(data)
	if err != nil {
		return nil, "", err
	}

	return b, "application/json", nil
}
