package authboss

import (
	"context"
	"net/http"
)

// Keys for use in HTMLData that are meaningful
const (

	// DataModules contains a map[string]bool of which modules are loaded
	// The bool is largely extraneous and can be ignored, if the module is
	// loaded it will be present in the map, if not it will be missing.
	DataModules = "modules"
)

// HTMLData is used to render templates with.
type HTMLData map[string]interface{}

// NewHTMLData creates HTMLData from key-value pairs. The input is a key-value
// slice, where odd elements are keys, and the following even element
// is their value.
func NewHTMLData(data ...interface{}) HTMLData {
	if len(data)%2 != 0 {
		panic("it should be a key value list of arguments.")
	}

	h := make(HTMLData)

	for i := 0; i < len(data)-1; i += 2 {
		k, ok := data[i].(string)
		if !ok {
			panic("Keys must be strings.")
		}

		h[k] = data[i+1]
	}

	return h
}

// Merge adds the data from other to h. If there are conflicting keys
// they are overwritten by other's values.
func (h HTMLData) Merge(other HTMLData) HTMLData {
	for k, v := range other {
		h[k] = v
	}
	return h
}

// MergeKV adds extra key-values to the HTMLData. The input is a key-value
// slice, where odd elements are keys, and the following even element
// is their value.
func (h HTMLData) MergeKV(data ...interface{}) HTMLData {
	if len(data)%2 != 0 {
		panic("It should be a key value list of arguments.")
	}

	for i := 0; i < len(data)-1; i += 2 {
		k, ok := data[i].(string)
		if !ok {
			panic("Keys must be strings.")
		}

		h[k] = data[i+1]
	}

	return h
}

// MergeDataInRequest edits the request pointer to point to a new request with
// a modified context that contains the merged data.
func MergeDataInRequest(r **http.Request, other HTMLData) {
	ctx := (*r).Context()
	currentIntf := ctx.Value(CTXKeyData)
	if currentIntf == nil {
		*r = (*r).WithContext(context.WithValue(ctx, CTXKeyData, other))
		return
	}

	current := currentIntf.(HTMLData)
	merged := current.Merge(other)
	*r = (*r).WithContext(context.WithValue(ctx, CTXKeyData, merged))
}
