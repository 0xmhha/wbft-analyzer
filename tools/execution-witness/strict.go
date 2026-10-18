package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

var ErrInput = errors.New("execution witness sources could not be verified")

func exactJSON(raw []byte, limit int, dst any) error {
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) {
		return ErrInput
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	budget := 2 << 20
	if walkJSON(d, 0, &budget) != nil {
		return ErrInput
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInput
	}
	if !exactFields(raw, reflect.TypeOf(dst).Elem()) {
		return ErrInput
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil {
		return ErrInput
	}
	return nil
}
func walkJSON(d *json.Decoder, depth int, budget *int) error {
	*budget--
	if depth > 48 || *budget < 0 {
		return ErrInput
	}
	token, err := d.Token()
	if err != nil {
		return ErrInput
	}
	switch token {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			s, ok := key.(string)
			if err != nil || !ok {
				return ErrInput
			}
			s = strings.ToLower(s)
			if seen[s] {
				return ErrInput
			}
			seen[s] = true
			if walkJSON(d, depth+1, budget) != nil {
				return ErrInput
			}
		}
		if end, err := d.Token(); err != nil || end != json.Delim('}') {
			return ErrInput
		}
	case json.Delim('['):
		for d.More() {
			if walkJSON(d, depth+1, budget) != nil {
				return ErrInput
			}
		}
		if end, err := d.Token(); err != nil || end != json.Delim(']') {
			return ErrInput
		}
	}
	return nil
}
func fields(t reflect.Type, out map[string]reflect.Type) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue
		}
		tag := strings.Split(f.Tag.Get("json"), ",")[0]
		if tag == "-" {
			continue
		}
		if f.Anonymous && tag == "" {
			fields(f.Type, out)
			continue
		}
		if tag == "" {
			tag = f.Name
		}
		out[tag] = f.Type
	}
}
func exactFields(raw json.RawMessage, t reflect.Type) bool {
	if t == reflect.TypeFor[json.RawMessage]() {
		return true
	}
	raw = bytes.TrimSpace(raw)
	for t.Kind() == reflect.Pointer {
		if bytes.Equal(raw, []byte("null")) {
			return true
		}
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		if len(raw) == 0 {
			return false
		}
		if raw[0] != '{' {
			return reflect.PointerTo(t).Implements(reflect.TypeFor[json.Unmarshaler]())
		}
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil || object == nil {
			return false
		}
		known := map[string]reflect.Type{}
		fields(t, known)
		for key, value := range object {
			field, ok := known[key]
			if !ok || !exactFields(value, field) {
				return false
			}
		}
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return true
		}
		var list []json.RawMessage
		if json.Unmarshal(raw, &list) != nil {
			return false
		}
		for _, v := range list {
			if !exactFields(v, t.Elem()) {
				return false
			}
		}
	case reflect.Map:
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil {
			return false
		}
		seen := map[string]bool{}
		for key, value := range object {
			if t.Key().Kind() == reflect.Array && t.Key().Elem().Kind() == reflect.Uint8 {
				normal := strings.TrimPrefix(strings.ToLower(key), "0x")
				if len(normal) > 2*t.Key().Len() || len(normal)%2 != 0 {
					return false
				}
				if _, err := hex.DecodeString(normal); err != nil {
					return false
				}
				normal = strings.Repeat("0", 2*t.Key().Len()-len(normal)) + normal
				if seen[normal] {
					return false
				}
				seen[normal] = true
			}
			if !exactFields(value, t.Elem()) {
				return false
			}
		}
	}
	return true
}
