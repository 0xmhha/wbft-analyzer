package governance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/source/jsonmeta"
	client "github.com/0xmhha/wbft-analyzer/internal/source/rpc"
)

// Requests fixes request order and scopes. Identity bookends must name the same
// source; moving heads and snapshots remain separate, explicitly non-atomic data.
func Requests(from, to string, instances []string, proposals []ProposalKey) ([]Request, error) {
	if _, _, err := Range(from, to); err != nil || len(instances) > 32 || len(proposals) > 128 {
		return nil, ErrInvalid
	}
	if _, err := addresses(instances, false); err != nil {
		return nil, err
	}
	seen := map[ProposalKey]bool{}
	for _, p := range proposals {
		key := ProposalKey{Instance: strings.ToLower(p.Instance), ID: p.ID}
		if !fixed(p.Instance, 20) || !quantity(p.ID, 64) || seen[key] {
			return nil, ErrInvalid
		}
		seen[key] = true
	}
	out := []Request{
		{Method: "wbft_nodeInfo", Params: []string{}, Scope: "identity-before"},
		{Method: "wbft_mirror", Params: []string{}, Scope: "snapshot-before"},
		{Method: "wbft_govOps", Params: []string{from, to}, Scope: "requested-range"},
		{Method: "wbft_mirrorFaults", Params: []string{from, to}, Scope: "requested-range"},
		{Method: "wbft_validatorChanges", Params: []string{from, to}, Scope: "requested-range"},
	}
	for _, instance := range instances {
		out = append(out, Request{Method: "wbft_mirrorState", Params: []string{instance, to}, Scope: "historical-state"})
	}
	for _, key := range proposals {
		out = append(out, Request{Method: "wbft_govProposal", Params: []string{key.Instance, key.ID}, Scope: "proposal-full-history-current-state"})
	}
	return append(out, Request{Method: "wbft_mirror", Params: []string{}, Scope: "snapshot-after"}, Request{Method: "wbft_nodeInfo", Params: []string{}, Scope: "identity-after"}), nil
}

func Load(path string) (Archive, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return Archive{}, "", err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil {
		return Archive{}, "", ErrInvalid
	}
	var a Archive
	if jsonmeta.Decode(raw, MaxBytes, true, &a) != nil {
		return Archive{}, "", ErrInvalid
	}
	return a, digest(raw), nil
}

func Normalize(a Archive) (Snapshot, error) {
	out := Snapshot{From: a.From, To: a.To, EnvelopeOrigin: a.EnvelopeOrigin, Calls: []Call{}}
	plan, err := Requests(a.From, a.To, a.Instances, a.Proposals)
	if err != nil || a.Format != Format || a.EnvelopeOrigin != "supplied" && a.EnvelopeOrigin != "client-reconstructed" || len(a.Replies) != len(plan) {
		return out, ErrInvalid
	}
	from, to, _ := Range(a.From, a.To)
	totalBytes := 0
	for i, r := range a.Replies {
		q := plan[i]
		if r.Method != q.Method || !slices.Equal(r.Params, q.Params) {
			return out, ErrInvalid
		}
		totalBytes += len(r.Response)
		if totalBytes > MaxBytes {
			return out, ErrInvalid
		}
		var env struct {
			Version string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Result  json.RawMessage `json:"result"`
			Error   json.RawMessage `json:"error"`
		}
		if decode(r.Response, &env, "jsonrpc", "id") != nil {
			return out, ErrInvalid
		}
		var id int64
		hasResult, hasError := len(env.Result) > 0, len(env.Error) > 0
		if env.Version != "2.0" || json.Unmarshal(env.ID, &id) != nil || id <= 0 || hasResult == hasError {
			return out, ErrInvalid
		}
		c := Call{Ordinal: i + 1, Request: q, Status: "unavailable", SHA256: digest(r.Response), Data: json.RawMessage("null")}
		if hasError {
			var e struct {
				Code int32 `json:"code"`
			}
			if decode(env.Error, &e, "code") != nil {
				return out, ErrInvalid
			}
			code := int(e.Code)
			c.ErrorCode = &code
		} else if !null(env.Result) {
			var value any
			switch q.Method {
			case "wbft_nodeInfo":
				n, e := identity(env.Result)
				err = e
				if i == 0 {
					out.Before = n
				} else {
					out.After = n
				}
				value = n
			case "wbft_mirror":
				value, err = mirror(env.Result)
			case "wbft_govOps":
				value, err = operations(env.Result, from, to, "")
			case "wbft_mirrorFaults":
				value, err = faults(env.Result, from, to)
			case "wbft_validatorChanges":
				value, err = changes(env.Result, from, to)
			case "wbft_mirrorState":
				value, err = state(env.Result, q.Params[0], a.To)
			case "wbft_govProposal":
				value, err = history(env.Result, ProposalKey{Instance: q.Params[0], ID: q.Params[1]})
			}
			if err != nil {
				return out, fmt.Errorf("governance request %d (%s): %w", i+1, q.Method, err)
			}
			c.Status = "available"
			c.Data, err = json.Marshal(value)
			if err != nil {
				return out, ErrInvalid
			}
		}
		out.Calls = append(out.Calls, c)
	}
	if out.Before.Address == "" || out.After.Address != out.Before.Address || out.After.ChainID != out.Before.ChainID || out.After.GenesisHash != out.Before.GenesisHash {
		return out, ErrInvalid
	}
	return out, nil
}

// Fetch issues read-only requests sequentially to one client. Error messages and
// endpoints stay outside the normalized snapshot. No rebuild method is issued.
func Fetch(ctx context.Context, c *client.Client, from, to string, instances []string, proposals []ProposalKey) (Archive, error) {
	a := Archive{Format: Format, EnvelopeOrigin: "client-reconstructed", From: from, To: to, Instances: slices.Clone(instances), Proposals: slices.Clone(proposals), Replies: []Reply{}}
	plan, err := Requests(from, to, instances, proposals)
	if err != nil {
		return a, err
	}
	totalBytes := 0
	for i, q := range plan {
		params := make([]any, 0, len(q.Params))
		for _, p := range q.Params {
			params = append(params, p)
		}
		answers, e := c.Batch(ctx, []client.Request{{Method: q.Method, Params: params}})
		if e != nil {
			if ctx.Err() != nil {
				return a, ctx.Err()
			}
			return a, ErrInvalid
		}
		env := map[string]any{"jsonrpc": "2.0", "id": 1}
		if answers[0].Error != nil {
			env["error"] = answers[0].Error
		} else {
			env["result"] = answers[0].Result
		}
		raw, e := json.Marshal(env)
		if e != nil {
			return a, ErrInvalid
		}
		totalBytes += len(raw)
		if totalBytes > MaxBytes {
			return a, ErrInvalid
		}
		a.Replies = append(a.Replies, Reply{Method: q.Method, Params: slices.Clone(q.Params), Response: raw})
		// Stop before other calls if the initial identity cannot be read.
		if i == 0 {
			if answers[0].Error != nil {
				return a, ErrInvalid
			}
			if _, e := identity(answers[0].Result); e != nil {
				return a, e
			}
		}
	}
	if _, err := Normalize(a); err != nil {
		return a, err
	}
	return a, nil
}
