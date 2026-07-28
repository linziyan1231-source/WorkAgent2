// Package jsonutil provides strict single-document JSON decoding helpers.
package jsonutil

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// ErrTrailingData classifies input that holds more than one JSON value.
var ErrTrailingData = errors.New("jsonutil: trailing data after JSON value")

// DecodeStrict decodes payload into destination, rejecting unknown fields and
// any data after the first JSON value. When useNumber is set, numbers in
// interface destinations are preserved as json.Number.
func DecodeStrict(payload []byte, destination any, useNumber bool) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if useNumber {
		decoder.UseNumber()
	}
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrTrailingData
	}
	return nil
}
