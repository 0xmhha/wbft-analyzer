// Package jsonmeta validates bounded metadata before typed projection.
package jsonmeta

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

var ErrInvalid = errors.New("invalid bounded JSON metadata")

// Decode rejects duplicate keys at every depth and trailing values. A subset
// projection may discard unknown fields only when strict is explicitly false.
func Decode(raw []byte, limit int, strict bool, dst any) error {
	if len(raw) == 0 || len(raw) > limit {
		return ErrInvalid
	}
	check := json.NewDecoder(bytes.NewReader(raw))
	if walk(check, 0) != nil {
		return ErrInvalid
	}
	if _, err := check.Token(); err != io.EOF {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if strict {
		d.DisallowUnknownFields()
	}
	if d.Decode(dst) != nil {
		return ErrInvalid
	}
	return nil
}

func walk(d *json.Decoder, depth int) error {
	if depth > 24 {
		return ErrInvalid
	}
	t, err := d.Token()
	if err != nil {
		return ErrInvalid
	}
	if t == json.Delim('{') {
		seen := map[string]bool{}
		for d.More() {
			k, err := d.Token()
			key, ok := k.(string)
			if err != nil || !ok || seen[key] {
				return ErrInvalid
			}
			seen[key] = true
			if walk(d, depth+1) != nil {
				return ErrInvalid
			}
		}
		if end, err := d.Token(); err != nil || end != json.Delim('}') {
			return ErrInvalid
		}
	} else if t == json.Delim('[') {
		for d.More() {
			if walk(d, depth+1) != nil {
				return ErrInvalid
			}
		}
		if end, err := d.Token(); err != nil || end != json.Delim(']') {
			return ErrInvalid
		}
	}
	return nil
}
