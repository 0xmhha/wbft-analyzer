package logs

import (
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// LegacyAssociation declares a fixed same-execution scope. Head witnesses
// corroborate the declaration; they do not prove wire receipt or step identity.
type LegacyAssociation struct {
	Address      string `json:"address"`
	Input        string `json:"input"`
	SHA256       string `json:"sha256"`
	NativeInput  string `json:"native_input"`
	NativeSHA256 string `json:"native_sha256"`
	From         string `json:"from_t"`
	To           string `json:"to_t"`
}

func validateLegacyAssociations(ds []LegacyAssociation, inputs []PreparedInput) error {
	if len(ds) > 100 {
		return errors.New("too many legacy associations")
	}
	byID := map[string]InputSummary{}
	for _, in := range inputs {
		byID[in.Summary.ID] = in.Summary
	}
	used, hashes := map[string]bool{}, map[string]bool{}
	for _, d := range ds {
		if len(d.Address) != 42 || !strings.HasPrefix(d.Address, "0x") {
			return errors.New("invalid legacy recording address")
		}
		if _, err := hex.DecodeString(d.Address[2:]); err != nil {
			return errors.New("invalid legacy recording address")
		}
		a, aok := byID[d.Input]
		b, bok := byID[d.NativeInput]
		from, e1 := time.Parse(time.RFC3339Nano, d.From)
		to, e2 := time.Parse(time.RFC3339Nano, d.To)
		if !aok || !bok || a.Kind == "events" || a.Profile != "gstable@740526d03" || b.Kind != "events" || a.SHA256 != d.SHA256 || b.SHA256 != d.NativeSHA256 || d.SHA256 == d.NativeSHA256 || used[d.Input] || hashes[d.SHA256] || e1 != nil || e2 != nil || !to.After(from) || to.Sub(from) > 24*time.Hour {
			return errors.New("invalid legacy association scope or fingerprint")
		}
		used[d.Input] = true
		hashes[d.SHA256] = true
	}
	return nil
}
