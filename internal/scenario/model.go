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
	Mode            string             `json:"mode,omitempty"`
	Assumptions     []string           `json:"assumptions,omitempty"`
	Substitutions   []CoreSubstitution `json:"substitutions,omitempty"`
	TransportInputs []string           `json:"transport_inputs,omitempty"`
	ModelSHA256     string             `json:"model_sha256"`
	Dataset         int64              `json:"dataset"`
	Version         string             `json:"fit_version"`
	Inputs          []Input            `json:"inputs"`
	ChainSHA256     string             `json:"chain_sha256"`
	CoreCommit      string             `json:"core_commit"`
	Seeds           []int64            `json:"seeds"`
}

type CoreSubstitution struct {
	Node         string `json:"node"`
	Source       Input  `json:"source"`
	Policy       string `json:"policy"`
	SigningState string `json:"signing_state"`
}

// SealProvenance hashes a canonical immutable execution scope. No input path,
// operational key, payload or signature is included in the exported scope.
func SealProvenance(p Provenance) (Provenance, string, error) {
	if p.Mode == "" {
		p.Mode = DeclaredRuntimeModel
	}
	if !ValidModel(p.Mode) || p.Mode == DeclaredRuntimeModel && (len(p.Assumptions) > 0 || len(p.Substitutions) > 0) || p.Mode == EmpiricalCoreModel && len(p.Assumptions) == 0 || len(p.Assumptions) > 32 || len(p.Substitutions) > 256 {
		return p, "", errors.New("invalid scenario model provenance")
	}
	if p.Dataset <= 0 || p.Version != FitVersion || !hexLength(p.ModelSHA256, 64) || !hexLength(p.ChainSHA256, 64) || !hexLength(p.CoreCommit, 40) || len(p.Inputs) == 0 || len(p.Inputs) > 512 || len(p.Seeds) == 0 || len(p.Seeds) > 128 {
		return p, "", errors.New("invalid scenario provenance")
	}
	p.Inputs = append([]Input(nil), p.Inputs...)
	p.Seeds = append([]int64(nil), p.Seeds...)
	p.Assumptions = append([]string(nil), p.Assumptions...)
	p.Substitutions = append([]CoreSubstitution(nil), p.Substitutions...)
	p.TransportInputs = append([]string(nil), p.TransportInputs...)
	assumptions := map[string]bool{}
	for _, a := range p.Assumptions {
		if a == "" || len(a) > 128 || assumptions[a] {
			return p, "", errors.New("invalid model assumption")
		}
		assumptions[a] = true
	}
	substitutions := map[string]bool{}
	for _, s := range p.Substitutions {
		if s.Node == "" || s.Source.Kind != "frames" || !hexLength(s.Source.SHA256, 64) || s.Source.Node != s.Node || s.Policy != "all_improvements_off" || s.SigningState != "fresh_test_keys_genesis_no_replay" || substitutions[s.Node] {
			return p, "", errors.New("invalid core substitution")
		}
		substitutions[s.Node] = true
	}
	seen := map[string]bool{}
	for _, i := range p.Inputs {
		if i.ID == "" || i.Kind == "" || i.Node == "" || !hexLength(i.SHA256, 64) || seen[i.ID] {
			return p, "", errors.New("invalid scenario input identity")
		}
		seen[i.ID] = true
	}
	if len(p.TransportInputs) > 256 {
		return p, "", errors.New("transport selection exceeds bound")
	}
	selected := map[string]bool{}
	for _, id := range p.TransportInputs {
		found := false
		for _, input := range p.Inputs {
			found = found || input.ID == id && (input.Kind == "journal" || input.Kind == "frames")
		}
		if !found || selected[id] {
			return p, "", errors.New("transport selection outside provenance")
		}
		selected[id] = true
	}
	for _, s := range p.Substitutions {
		found := false
		for _, i := range p.Inputs {
			found = found || i == s.Source
		}
		if !found {
			return p, "", errors.New("substitution source outside provenance")
		}
	}
	seeds := map[int64]bool{}
	for _, s := range p.Seeds {
		if seeds[s] {
			return p, "", errors.New("duplicate scenario seed")
		}
		seeds[s] = true
	}
	sort.Slice(p.Inputs, func(i, j int) bool { return p.Inputs[i].ID < p.Inputs[j].ID })
	sort.Strings(p.Assumptions)
	sort.Strings(p.TransportInputs)
	sort.Slice(p.Substitutions, func(i, j int) bool { return p.Substitutions[i].Node < p.Substitutions[j].Node })
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
