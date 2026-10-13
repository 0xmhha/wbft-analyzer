// Package observe reads bounded, metadata-only native observation RPC captures.
// Header participation is never event capture or a message-delivery witness.
package observe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"regexp"
	"strings"

	client "github.com/0xmhha/wbft-analyzer/internal/source/rpc"
	"github.com/0xmhha/wbft/observe/participation"
	native "github.com/0xmhha/wbft/rpc"
)

const Format = "wbft-analyzer-observe/1"
const Normalizer = "wbft-observe-normalization/1"
const MaxBytes = 32 << 20
const MaxCalls = 4096

// Reply binds a captured JSON-RPC envelope to its exact request. Hashes bind
// the supplied envelope bytes; live envelopes are reconstructed from the client
// result/error, not claimed to be original network packet bytes.
type Reply struct {
	Method   string          `json:"method"`
	Params   []string        `json:"params"`
	Response json.RawMessage `json:"response"`
}
type Archive struct {
	Format  string  `json:"format"`
	From    string  `json:"from"`
	To      string  `json:"to"`
	Replies []Reply `json:"replies"`
}
type Call struct {
	Ordinal   int64           `json:"ordinal"`
	Method    string          `json:"method"`
	Params    []string        `json:"params"`
	Status    string          `json:"status"`
	ErrorCode *int            `json:"error_code,omitempty"`
	SHA256    string          `json:"sha256"`
	Data      json.RawMessage `json:"data"`
}

// Copy omits aggregate signature bytes, which are not needed for participation.
// Null seals and empty seals remain distinguishable.
type Copy struct {
	Number    string    `json:"number"`
	Hash      string    `json:"hash"`
	Round     uint32    `json:"round"`
	Path      string    `json:"path"`
	Prepared  *[]uint32 `json:"prepared"`
	Committed *[]uint32 `json:"committed"`
}
type Comparison struct {
	Status          string                 `json:"status"`
	Computed        *participation.Summary `json:"computed"`
	Reported        *participation.Summary `json:"reported"`
	DifferentFields []string               `json:"different_fields"`
}
type Snapshot struct {
	From       string          `json:"from"`
	To         string          `json:"to"`
	Node       native.NodeInfo `json:"node"`
	Calls      []Call          `json:"calls"`
	Comparison Comparison      `json:"comparison"`
}

var label = regexp.MustCompile(`^[A-Za-z0-9_.@:+-]{1,128}$`)

// Range accepts canonical decimal full heights, including values above uint64.
func Range(from, to string) (*big.Int, *big.Int, error) {
	a, ok := number(from)
	if !ok {
		return nil, nil, errors.New("invalid full from height")
	}
	b, ok := number(to)
	if !ok || b.Cmp(a) < 0 || new(big.Int).Sub(b, a).Cmp(big.NewInt(1024)) >= 0 {
		return nil, nil, errors.New("observation range must contain 1..1024 full heights")
	}
	return a, b, nil
}
func number(s string) (*big.Int, bool) {
	if s == "" || len(s) > 156 || len(s) > 1 && s[0] == '0' {
		return nil, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return nil, false
		}
	}
	n, ok := new(big.Int).SetString(s, 10)
	return n, ok
}
func hash(s string) bool {
	if len(s) != 66 || !strings.HasPrefix(s, "0x") {
		return false
	}
	_, e := hex.DecodeString(s[2:])
	return e == nil
}
func address(s string) bool {
	if len(s) != 42 || !strings.HasPrefix(s, "0x") {
		return false
	}
	_, e := hex.DecodeString(s[2:])
	return e == nil
}
func decode(raw []byte, out any) error {
	if e := uniqueJSON(raw); e != nil {
		return e
	}

	d := json.NewDecoder(bytes.NewReader(raw))
	if e := d.Decode(out); e != nil {
		return errors.New("invalid typed observation result")
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing observation result")
	}
	return nil
}
func Load(path string) (Archive, string, error) {
	f, e := os.Open(path)
	if e != nil {
		return Archive{}, "", e
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if e != nil || len(raw) > MaxBytes {
		return Archive{}, "", errors.New("observation archive exceeds limit or could not be read")
	}
	if e := uniqueJSON(raw); e != nil {
		return Archive{}, "", e
	}
	var a Archive
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&a) != nil {
		return a, "", errors.New("invalid observation archive")
	}
	if _, e := d.Token(); e != io.EOF {
		return a, "", errors.New("trailing observation archive")
	}
	sum := sha256.Sum256(raw)
	return a, hex.EncodeToString(sum[:]), nil
}

// Normalize refuses duplicate requests, foreign node identities and truncated
// participation ranges. Per-method RPC errors/nulls remain explicit unavailable
// calls. Arbitrary result properties and server error messages are not retained.
func Normalize(a Archive) (Snapshot, error) {
	out := Snapshot{From: a.From, To: a.To, Calls: []Call{}, Comparison: Comparison{Status: "unavailable", DifferentFields: []string{}}}
	from, to, e := Range(a.From, a.To)
	if e != nil {
		return out, e
	}
	if a.Format != Format || len(a.Replies) == 0 || len(a.Replies) > MaxCalls {
		return out, errors.New("invalid observation format or call count")
	}
	seen := map[string]bool{}
	haveNode := false
	totalBytes := 0
	for i, r := range a.Replies {
		keyRaw, _ := json.Marshal([]any{r.Method, r.Params})
		key := string(keyRaw)
		if seen[key] {
			return out, errors.New("duplicate observation request")
		}
		seen[key] = true
		if e = validRequest(r, a.From, a.To); e != nil {
			return out, e
		}
		totalBytes += len(r.Response)
		if totalBytes > MaxBytes {
			return out, errors.New("observation response exceeds limit")
		}
		var response struct {
			Version string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Result  json.RawMessage `json:"result"`
			Error   *client.Error   `json:"error"`
		}
		if e = decode(r.Response, &response); e != nil {
			return out, e
		}
		var id int64
		if response.Version != "2.0" || json.Unmarshal(response.ID, &id) != nil || id <= 0 || (response.Error == nil && len(response.Result) == 0) || (response.Error != nil && len(response.Result) > 0) {
			return out, errors.New("invalid observation JSON-RPC envelope")
		}
		sum := sha256.Sum256(r.Response)
		c := Call{Ordinal: int64(i + 1), Method: r.Method, Params: r.Params, Status: "unavailable", SHA256: hex.EncodeToString(sum[:]), Data: json.RawMessage(`null`)}
		if response.Error != nil {
			code := response.Error.Code
			c.ErrorCode = &code
			out.Calls = append(out.Calls, c)
			continue
		}
		if bytes.Equal(bytes.TrimSpace(response.Result), []byte("null")) {
			out.Calls = append(out.Calls, c)
			continue
		}
		var value any
		switch r.Method {
		case "wbft_nodeInfo":
			var fields map[string]json.RawMessage
			_ = json.Unmarshal(response.Result, &fields)
			for _, key := range []string{"impl", "address", "validator", "chainId", "genesisHash", "head", "mode", "version", "build", "logProfile", "rulesDigest"} {
				if len(fields[key]) == 0 || bytes.Equal(fields[key], []byte("null")) {
					return out, errors.New("required native node metadata missing")
				}
			}
			var n native.NodeInfo
			if e = decode(response.Result, &n); e != nil {
				return out, e
			}
			if n.Impl != "wbft" || n.ChainID == nil || n.ChainID.Sign() < 0 || !hash(n.GenesisHash.String()) || !hash(n.Head.Hash.String()) || (!label.MatchString(n.Version) && n.Version != "(devel)") || !label.MatchString(n.Build) || !label.MatchString(n.LogProfile) || (n.Mode != "standalone" && n.Mode != "embedded") {
				return out, errors.New("invalid native node identity")
			}
			if _, ok := number(n.Head.Number); !ok {
				return out, errors.New("invalid node head")
			}
			if n.SignFloor != "" {
				if _, ok := number(n.SignFloor); !ok {
					return out, errors.New("invalid sign floor")
				}
			}
			for _, x := range n.Improvements {
				if !label.MatchString(x.Name) || (x.Source != "profile" && x.Source != "app") {
					return out, errors.New("invalid improvement metadata")
				}
			}
			for k, v := range n.RuleActivations {
				if !label.MatchString(string(k)) {
					return out, errors.New("invalid rule metadata")
				}
				if _, ok := number(v); !ok {
					return out, errors.New("invalid rule activation")
				}
			}
			if n.BLSPublicKey != "" {
				if len(n.BLSPublicKey) != 98 || !strings.HasPrefix(n.BLSPublicKey, "0x") {
					return out, errors.New("invalid public key")
				}
				if _, e = hex.DecodeString(n.BLSPublicKey[2:]); e != nil {
					return out, errors.New("invalid public key")
				}
			}
			if haveNode {
				return out, errors.New("multiple node identities")
			}
			haveNode = true
			out.Node = n
			value = n
		case "wbft_configAt":
			var cfg native.ConfigAtResult
			if e = decode(response.Result, &cfg); e != nil {
				return out, e
			}
			if cfg.Number != r.Params[0] || len(cfg.Transitions) > 1024 {
				return out, errors.New("configuration request/result mismatch")
			}
			for _, tr := range cfg.Transitions {
				n, ok := number(tr.Block)
				want, _ := number(cfg.Number)
				if !ok || n.Cmp(want) > 0 {
					return out, errors.New("invalid configuration transition")
				}
			}
			value = cfg
		case "wbft_participation":
			var records []participation.Record
			if e = decode(response.Result, &records); e != nil {
				return out, e
			}
			if e = validateRecords(records, from, to); e != nil {
				return out, e
			}
			value = records
			s := participation.Summarize(records)
			out.Comparison.Computed = &s
		case "wbft_participationSummary":
			var s participation.Summary
			if e = decode(response.Result, &s); e != nil {
				return out, e
			}
			if s.From != a.From || s.To != a.To || len(s.Validators) > 65536 || s.Heights < 0 || s.Gaps < 0 || s.Local < 0 {
				return out, errors.New("invalid reported summary")
			}
			value = s
			out.Comparison.Reported = &s
		case "wbft_headerCopy":
			var h native.HeaderCopyResult
			if e = decode(response.Result, &h); e != nil {
				return out, e
			}
			n, ok := number(h.Number)
			if !ok || n.Cmp(from) < 0 || n.Cmp(to) > 0 || h.Hash != r.Params[0] || !hash(h.Hash) || !oneOf(h.Path, "sealed_locally", "imported", "synced", "unknown") {
				return out, errors.New("header copy request/result mismatch")
			}
			cp := Copy{Number: h.Number, Hash: h.Hash, Round: h.Round, Path: h.Path}
			if h.PreparedSeal != nil {
				xs := h.PreparedSeal.Sealers
				if xs == nil {
					xs = []uint32{}
				}
				cp.Prepared = &xs
			}
			if h.CommittedSeal != nil {
				xs := h.CommittedSeal.Sealers
				if xs == nil {
					xs = []uint32{}
				}
				cp.Committed = &xs
			}
			value = cp
		}
		c.Status = "available"
		c.Data, e = json.Marshal(value)
		if e != nil {
			return out, e
		}
		out.Calls = append(out.Calls, c)
	}
	if !haveNode {
		return out, errors.New("native node identity unavailable")
	}
	for _, m := range []string{"wbft_nodeInfo", "wbft_participation", "wbft_participationSummary"} {
		found := false
		for _, c := range out.Calls {
			found = found || c.Method == m
		}
		if !found {
			return out, errors.New("required observation request missing")
		}
	}
	out.Comparison = compare(out.Comparison)
	return out, nil
}
func oneOf(x string, values ...string) bool {
	for _, v := range values {
		if x == v {
			return true
		}
	}
	return false
}
func validRequest(r Reply, from, to string) error {
	switch r.Method {
	case "wbft_nodeInfo":
		if len(r.Params) == 0 {
			return nil
		}
	case "wbft_participation", "wbft_participationSummary":
		if len(r.Params) == 2 && r.Params[0] == from && r.Params[1] == to {
			return nil
		}
	case "wbft_configAt":
		if len(r.Params) == 1 {
			n, ok := number(r.Params[0])
			a, b, _ := Range(from, to)
			if ok && n.Cmp(a) >= 0 && n.Cmp(b) <= 0 {
				return nil
			}
		}
	case "wbft_headerCopy":
		if len(r.Params) == 1 && hash(r.Params[0]) {
			return nil
		}
	}
	return errors.New("invalid observation method or request scope")
}
func validateRecords(records []participation.Record, from, to *big.Int) error {
	count := new(big.Int).Sub(to, from).Int64() + 1
	if int64(len(records)) != count {
		return errors.New("participation did not return every requested height")
	}
	sums := map[string]*big.Int{}
	for i, r := range records {
		expected := new(big.Int).Add(from, big.NewInt(int64(i))).String()
		if r.Height != expected {
			return errors.New("participation order or height mismatch")
		}
		if r.Gap {
			if r.Source != "" || r.Hash != "" || r.Round != "" || r.Proposer != "" || r.Time != 0 || len(r.Rounds) > 0 || len(r.Validators) > 0 {
				return errors.New("gap contains participation claims")
			}
			continue
		}
		if !oneOf(r.Source, "local", "header") || !hash(r.Hash) || !address(r.Proposer) {
			return errors.New("invalid participation identity or source")
		}
		if _, ok := number(r.Round); !ok {
			return errors.New("invalid committed round")
		}
		if len(r.Rounds) > 4096 || len(r.Validators) > 4096 {
			return errors.New("participation height exceeds metadata bounds")
		}
		rounds := map[string]bool{}
		for _, rd := range r.Rounds {
			if _, ok := number(rd.Round); !ok || rounds[rd.Round] || !address(rd.Proposer) || !oneOf(rd.Outcome, "", "committed", "round_change") || !oneOf(rd.Cause, "", "timeout", "f_plus_one", "finalize_fail", "catch_up") {
				return errors.New("invalid participation round")
			}
			rounds[rd.Round] = true
		}
		validators := map[string]bool{}
		for _, row := range r.Validators {
			k := row.Round + ":" + strings.ToLower(row.Validator)
			if _, ok := number(row.Round); !ok || !address(row.Validator) || validators[k] {
				return errors.New("invalid or duplicate validator participation")
			}
			validators[k] = true
			for phase, s := range []*participation.Seen{row.Preprepare, row.Prepare, row.Commit, row.RoundChange} {
				if s == nil {
					continue
				}
				if r.Source == "header" || s.At.IsZero() || !oneOf(s.Via, "direct", "backlog", "self") || !oneOf(s.Outcome, "ACCEPT", "IGNORE") || s.Peer != "" && !address(s.Peer) || s.Key != "" && !hash(s.Key) {
					return errors.New("invalid message observation or header-only arrival claim")
				}
				if s.DelayMs != nil && s.Via != "self" {
					key := row.Validator + ":" + fmt.Sprint(phase)
					if sums[key] == nil {
						sums[key] = new(big.Int)
					}
					sums[key].Add(sums[key], big.NewInt(*s.DelayMs))
					if !sums[key].IsInt64() {
						return errors.New("participation delay aggregate exceeds int64")
					}
				}

			}
		}
	}
	return nil
}
func compare(c Comparison) Comparison {
	if c.Computed == nil || c.Reported == nil {
		return c
	}
	c.Status = "match"
	var a, b map[string]json.RawMessage
	ar, _ := json.Marshal(c.Computed)
	br, _ := json.Marshal(c.Reported)
	_ = json.Unmarshal(ar, &a)
	_ = json.Unmarshal(br, &b)
	for _, field := range []string{"from", "to", "heights", "gaps", "local", "validators"} {
		if !bytes.Equal(a[field], b[field]) {
			c.DifferentFields = append(c.DifferentFields, field)
		}
	}
	if len(c.DifferentFields) > 0 {
		c.Status = "different"
	}
	return c
}

// Fetch gathers read-only RPC calls; it is a collection of claims, not an atomic
// node snapshot. Full historical range replies and optional availability remain
// independently recorded. Requests use the existing bounded/rate-limited client.
func Fetch(ctx context.Context, c *client.Client, from, to string) (Archive, error) {
	a := Archive{Format: Format, From: from, To: to, Replies: []Reply{}}
	lo, hi, e := Range(from, to)
	if e != nil {
		return a, e
	}
	totalBytes := 0
	call := func(requests []client.Request) error {
		answers, e := c.Batch(ctx, requests)
		if e != nil {
			return e
		}
		for i, x := range answers {
			r := Reply{Method: requests[i].Method, Params: []string{}}
			for _, p := range requests[i].Params {
				r.Params = append(r.Params, p.(string))
			}
			reply := map[string]any{"jsonrpc": "2.0", "id": i + 1}
			if x.Error != nil {
				reply["error"] = x.Error
			} else {
				reply["result"] = x.Result
			}
			r.Response, _ = json.Marshal(reply)
			totalBytes += len(r.Response)
			if totalBytes > MaxBytes {
				return errors.New("observation collection exceeds 32 MiB")
			}
			a.Replies = append(a.Replies, r)
		}
		return nil
	}
	if e = call([]client.Request{{Method: "wbft_nodeInfo"}, {Method: "wbft_participation", Params: []any{from, to}}, {Method: "wbft_participationSummary", Params: []any{from, to}}}); e != nil {
		return a, e
	}
	// Refuse a malformed identity/range before issuing height-specific calls.
	snap, e := Normalize(a)
	if e != nil {
		return a, e
	}
	requests := []client.Request{}
	hashes := map[string]bool{}
	for _, r := range snap.Calls {
		if r.Method == "wbft_participation" && r.Status == "available" {
			var rows []participation.Record
			_ = json.Unmarshal(r.Data, &rows)
			for _, v := range rows {
				if !v.Gap && !hashes[v.Hash] {
					hashes[v.Hash] = true
					requests = append(requests, client.Request{Method: "wbft_headerCopy", Params: []any{v.Hash}})
				}
			}
		}
	}
	for h := new(big.Int).Set(lo); h.Cmp(hi) <= 0; h.Add(h, big.NewInt(1)) {
		requests = append(requests, client.Request{Method: "wbft_configAt", Params: []any{h.String()}})
	}
	for len(requests) > 0 {
		n := min(len(requests), 100)
		if e = call(requests[:n]); e != nil {
			return a, e
		}
		requests = requests[n:]
	}
	if _, e = Normalize(a); e != nil {
		return a, fmt.Errorf("invalid observation collection: %w", e)
	}
	return a, nil
}

// JSON object keys must be unique at every depth; last-key-wins decoding could
// otherwise replace request identity, availability or a full-height claim.
func uniqueJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 128 {
			return errors.New("observation nesting exceeds limit")
		}
		t, e := d.Token()
		if e != nil {
			return errors.New("invalid observation JSON")
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return errors.New("invalid observation object")
				}
				name, ok := k.(string)
				if !ok || keys[name] {
					return errors.New("duplicate observation JSON key")
				}
				keys[name] = true
				if e = value(depth + 1); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e = value(depth + 1); e != nil {
					return e
				}
			}
		default:
			return errors.New("unexpected observation delimiter")
		}
		end, e := d.Token()
		if e != nil || delim == '{' && end != json.Delim('}') || delim == '[' && end != json.Delim(']') {
			return errors.New("invalid observation closure")
		}
		return nil
	}
	if e := value(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing observation JSON")
	}
	return nil
}
