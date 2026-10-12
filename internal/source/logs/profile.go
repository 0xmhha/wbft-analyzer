// Package logs normalizes bounded JSON log streams using implementation
// profiles. Persisted records contain metadata, never payload or data bytes.
package logs

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"

	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/observe/logcat"
)

//go:embed profiles/*.json
var profiles embed.FS

type Entry struct {
	Kind     event.Kind        `json:"kind"`
	Module   string            `json:"module"`
	Level    string            `json:"level"`
	Msg      string            `json:"msg"`
	Template bool              `json:"template"`
	Fields   map[string]string `json:"fields"`
	pattern  *regexp.Regexp
}
type Profile struct {
	Format  string  `json:"format"`
	ID      string  `json:"id"`
	Entries []Entry `json:"entries"`
	SHA256  string  `json:"-"`
	legacy  bool
	byLine  map[[3]string]*Entry
	modules map[string]bool
}

func LoadProfile(path string) (*Profile, error) {
	var raw []byte
	var err error
	switch path {
	case "", "gstable@740526d03":
		raw, err = profiles.ReadFile("profiles/gstable@740526d03.json")
	case "wbft":
		raw, err = json.Marshal(logcat.BuildProfile())
	default:
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	return ParseProfile(raw)
}
func ParseProfile(raw []byte) (*Profile, error) {
	var p Profile
	if json.Unmarshal(raw, &p) != nil || p.Format != logcat.ProfileFormat || len(p.Entries) == 0 || len(p.Entries) > 1000 {
		return nil, errors.New("invalid log profile")
	}
	p.legacy = p.ID == "gstable@740526d03"
	if !p.legacy && !regexp.MustCompile(`^wbft@[0-9a-f]{12}$`).MatchString(p.ID) {
		return nil, errors.New("unsupported log profile ID")
	}
	sum := sha256.Sum256(raw)
	p.SHA256 = hex.EncodeToString(sum[:])
	p.byLine = map[[3]string]*Entry{}
	p.modules = map[string]bool{}
	kinds := map[event.Kind]bool{}
	for _, k := range logcat.EventKinds() {
		kinds[event.Kind(k)] = true
	}
	kinds[event.LogConfig] = true
	for i := range p.Entries {
		e := &p.Entries[i]
		if !kinds[e.Kind] || len(e.Msg) > 512 || e.Msg == "" || !validLevel(e.Level) {
			return nil, errors.New("invalid profile entry")
		}
		if p.legacy && (e.Module != "" || !strings.HasPrefix(e.Msg, "WBFT: ")) {
			return nil, errors.New("invalid legacy profile entry")
		}
		if e.Template {
			if e.Msg != "WBFT:   - candidates[%d]" {
				return nil, errors.New("unsupported log template")
			}
			e.pattern = regexp.MustCompile(`^WBFT:   - candidates\[[0-9]+\]$`)
		}
		key := [3]string{e.Msg, e.Module, e.Level}
		if p.byLine[key] != nil {
			return nil, errors.New("duplicate profile entry")
		}
		for k, v := range e.Fields {
			if !safeEnum(k, v) {
				return nil, errors.New("invalid profile metadata")
			}
		}
		p.byLine[key] = e
		p.modules[e.Module] = true
	}
	return &p, nil
}
func validLevel(s string) bool {
	return s == "trace" || s == "debug" || s == "info" || s == "warn" || s == "error"
}
func (p *Profile) match(msg, module, level string) *Entry {
	if e := p.byLine[[3]string{msg, module, level}]; e != nil {
		return e
	}
	for i := range p.Entries {
		e := &p.Entries[i]
		if e.pattern != nil && e.Module == module && e.Level == level && e.pattern.MatchString(msg) {
			return e
		}
	}
	return nil
}
func (p *Profile) relevant(msg, module string) bool {
	if p.legacy {
		return strings.HasPrefix(msg, "WBFT: ")
	}
	return p.modules[module] && (module != "node" || msg == "log settings")
}

// Metadata is an allowlist: arbitrary errors, proposals, payloads, bytes,
// nested objects and unknown keys cannot cross the source/store boundary.
func Metadata(m map[string]json.RawMessage) map[string]any {
	out := map[string]any{}
	for k, raw := range m {
		s := scalar(raw)
		if enumKeys[k] {
			if safeEnum(k, s) {
				out[k] = s
			}
			continue
		}
		if addressKeys[k] && addressPattern.MatchString(s) {
			out[k] = strings.ToLower(s)
			continue
		}
		if hashKeys[k] && hashPattern.MatchString(s) {
			out[k] = strings.ToLower(s)
			continue
		}
		if integerKeys[k] {
			if n := decimal(s); n != "" {
				out[k] = n
			}
			continue
		}
		if k == "timeout" {
			var n json.Number
			d := json.NewDecoder(bytes.NewReader(raw))
			d.UseNumber()
			if d.Decode(&n) == nil {
				if f, err := n.Float64(); err == nil && f >= 0 && f <= 1e12 {
					out[k] = f
				}
			}
			continue
		}
		if k == "next.IsProposer" {
			var b bool
			if json.Unmarshal(raw, &b) == nil {
				out[k] = b
			}
		}
	}
	return out
}

var addressPattern = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
var hashPattern = regexp.MustCompile(`^0x[0-9a-fA-F]{64}$`)
var integerPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,155})$`)

func decimal(s string) string {
	if integerPattern.MatchString(s) {
		return s
	}
	return ""
}
func scalar(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	if integerPattern.Match(raw) {
		return string(raw)
	}
	return ""
}

var addressKeys = keySet("address", "author", "source", "from", "sender", "msg.source", "next.proposer", "old.proposer", "proposer", "validator", "addr", "peer")
var hashKeys = keySet("hash", "block.hash", "proposal.hash", "lastProposal.hash", "digest", "prepare", "dedup_key")
var integerKeys = keySet("current.sequence", "current.round", "msg.sequence", "msg.round", "msg.code", "next.seq", "next.round", "next.size", "number", "block.number", "proposal.number", "lastProposal.number", "sequence", "round", "prepares.count", "commits.count", "quorum", "F", "higherRoundChanges.count", "currentRoundChanges.count", "backlogs_size", "diligence", "step", "code", "size")
var enumKeys = keySet("phase", "what", "timer", "action", "outcome", "cause", "path", "state", "old.state", "new.state", "branch", "via")

func keySet(keys ...string) map[string]bool {
	m := map[string]bool{}
	for _, k := range keys {
		m[k] = true
	}
	return m
}
func safeEnum(k, v string) bool {
	var vs string
	switch k {
	case "phase":
		vs = "PRE-PREPARE|PREPARE|COMMIT|ROUND-CHANGE"
	case "what":
		vs = "PREPARE|COMMIT|ROUND_CHANGE|F_PLUS_ONE"
	case "timer":
		vs = "round|retry"
	case "action":
		vs = "handle"
	case "outcome":
		vs = "ACCEPT|IGNORE|DROP_SILENT|DISCONNECT|PENDING"
	case "cause":
		vs = "broadcast|gossip|relay|retry|reconnect|replay|direct|start|new_head|timeout|f_plus_one|finalize_fail"
	case "path":
		vs = "sealed_locally|imported|synced"
	case "state", "old.state", "new.state":
		vs = "Accept request|Preprepared|Prepared|Committed"
	case "branch":
		vs = "INITIAL|CATCH_UP|CHANGE_ROUND"
	case "via":
		vs = "local|direct|relay"
	default:
		return false
	}
	for _, s := range strings.Split(vs, "|") {
		if s == v {
			return true
		}
	}
	return false
}
