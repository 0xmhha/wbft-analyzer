package whatif

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"strconv"
	"time"
)

type Policy struct {
	Request *string `json:"request_timeout_seconds,omitempty"`
	Maximum *string `json:"max_request_timeout_seconds,omitempty"`
}

func (p Policy) Validate() error {
	if p.Request == nil && p.Maximum == nil {
		return ErrEvidence
	}
	for _, value := range []*string{p.Request, p.Maximum} {
		if value == nil {
			continue
		}
		if !decimal(*value, true, 64) {
			return ErrEvidence
		}
		n, err := strconv.ParseUint(*value, 10, 64)
		if err != nil || n > uint64(math.MaxInt64/int64(time.Second)) {
			return ErrEvidence
		}
	}
	if p.Request != nil && *p.Request == "0" {
		return ErrEvidence
	}
	return nil
}
func (p *Policy) UnmarshalJSON(raw []byte) error {
	if len(raw) > 4096 || rejectDuplicateKeys(json.NewDecoder(bytes.NewReader(raw)), 0) != nil {
		return ErrEvidence
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) == 0 {
		return ErrEvidence
	}
	for _, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return ErrEvidence
		}
	}
	type plain Policy
	var parsed plain
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&parsed) != nil {
		return ErrEvidence
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrEvidence
	}
	out := Policy(parsed)
	if err := out.Validate(); err != nil {
		return err
	}
	*p = out
	return nil
}
func (p Policy) Canonical() ([]byte, string, error) {
	if err := p.Validate(); err != nil {
		return nil, "", err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, "", err
	}
	hash := sha256.Sum256(raw)
	return raw, hex.EncodeToString(hash[:]), nil
}
