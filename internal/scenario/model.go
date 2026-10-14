package scenario

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

type Input struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Node   string `json:"node"`
	SHA256 string `json:"sha256"`
}

type Provenance struct {
	ModelSHA256 string  `json:"model_sha256"`
	Dataset     int64   `json:"dataset"`
	Version     string  `json:"fit_version"`
	Inputs      []Input `json:"inputs"`
	ChainSHA256 string  `json:"chain_sha256"`
	CoreCommit  string  `json:"core_commit"`
	Seeds       []int64 `json:"seeds"`
}

// SealProvenance hashes a canonical immutable execution scope. No input path,
// operational key, payload or signature is included in the exported scope.
func SealProvenance(p Provenance) (Provenance, string, error) {
	if p.Dataset <= 0 || p.Version != FitVersion || !hexLength(p.ModelSHA256, 64) || !hexLength(p.ChainSHA256, 64) || !hexLength(p.CoreCommit, 40) || len(p.Inputs) == 0 || len(p.Inputs) > 512 || len(p.Seeds) == 0 || len(p.Seeds) > 128 {
		return p, "", errors.New("invalid scenario provenance")
	}
	p.Inputs = append([]Input(nil), p.Inputs...)
	p.Seeds = append([]int64(nil), p.Seeds...)
	seen := map[string]bool{}
	for _, i := range p.Inputs {
		if i.ID == "" || i.Kind == "" || i.Node == "" || !hexLength(i.SHA256, 64) || seen[i.ID] {
			return p, "", errors.New("invalid scenario input identity")
		}
		seen[i.ID] = true
	}
	seeds := map[int64]bool{}
	for _, s := range p.Seeds {
		if seeds[s] {
			return p, "", errors.New("duplicate scenario seed")
		}
		seeds[s] = true
	}
	sort.Slice(p.Inputs, func(i, j int) bool { return p.Inputs[i].ID < p.Inputs[j].ID })
	// Seed order is execution order and remains part of the identity.
	raw, err := json.Marshal(p)
	if err != nil {
		return p, "", err
	}
	sum := sha256.Sum256(raw)
	return p, hex.EncodeToString(sum[:]), nil
}

func hexLength(s string, n int) bool {
	if len(s) != n || s != strings.ToLower(s) {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
