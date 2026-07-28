// Package httpjson provides shared HTTP request JSON decoding helpers.
package httpjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// Decode reads at most maximum bytes of a request body and decodes exactly one
// JSON value, rejecting unknown fields. The buffered payload is zeroed before
// return so request secrets do not linger in reusable memory.
func Decode(request *http.Request, destination any, maximum int64) error {
	payload, err := io.ReadAll(io.LimitReader(request.Body, maximum+1))
	if err != nil {
		return err
	}
	if int64(len(payload)) > maximum {
		clear(payload)
		return errors.New("request body is too large")
	}
	defer clear(payload)
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON value")
	}
	return nil
}
