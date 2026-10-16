package governance

import (
	"encoding/json"
	"fmt"
	"strings"
)

func operations(raw json.RawMessage, from, to uint64, instance string) ([]Operation, error) {
	var rows []json.RawMessage
	if decode(raw, &rows) != nil || rows == nil || len(rows) > maxRows {
		return nil, ErrInvalid
	}
	out := make([]Operation, 0, len(rows))
	seen := map[string]bool{}
	txHashes := map[string]string{}
	for _, row := range rows {
		var w struct {
			Number              string            `json:"number"`
			Tx                  uint32            `json:"tx"`
			TxHash              string            `json:"txHash"`
			Path                []uint32          `json:"path"`
			From                string            `json:"from"`
			Instance            string            `json:"instance"`
			Input               string            `json:"input"`
			Effective           bool              `json:"effective"`
			View                bool              `json:"view"`
			Result              string            `json:"result"`
			Logs                []json.RawMessage `json:"logs"`
			Verified            bool              `json:"verified"`
			ExecutingProposalID *string           `json:"executingProposalId"`
			ValidatorChange     json.RawMessage   `json:"validatorChange"`
		}
		if decode(row, &w, "number", "tx", "txHash", "from", "instance", "input", "effective", "view", "result", "logs", "verified") != nil || !within(w.Number, from, to) || !fixed(w.TxHash, 32) || !fixed(w.From, 20) || !fixed(w.Instance, 20) || instance != "" && !strings.EqualFold(w.Instance, instance) || len(w.Path) > 128 || len(w.Logs) > 4096 || len(w.Result) > 4096 || w.ExecutingProposalID != nil && !quantity(*w.ExecutingProposalID, 64) {
			return nil, ErrInvalid
		}
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(row, &fields)
		for _, k := range []string{"path", "executingProposalId", "validatorChange"} {
			if len(fields[k]) == 0 {
				return nil, ErrInvalid
			}
		}
		path := append([]uint32{}, w.Path...)
		key := fmt.Sprintf("%s/%d/%v", w.Number, w.Tx, path)
		if seen[key] {
			return nil, ErrInvalid
		}
		seen[key] = true
		txKey := fmt.Sprintf("%s/%d", w.Number, w.Tx)
		txHash := strings.ToLower(w.TxHash)
		if previous := txHashes[txKey]; previous != "" && previous != txHash {
			return nil, ErrInvalid
		}
		txHashes[txKey] = txHash
		input, err := hexBytes(w.Input)
		if err != nil {
			return nil, err
		}
		selector := ""
		if len(input) >= 4 {
			selector = fmt.Sprintf("0x%x", input[:4])
		}
		logs := make([]Log, 0, len(w.Logs))
		for _, rawLog := range w.Logs {
			var log struct {
				Address string   `json:"address"`
				Topics  []string `json:"topics"`
				Data    string   `json:"data"`
			}
			if decode(rawLog, &log, "address", "data") != nil || !hasFields(rawLog, "topics") || !fixed(log.Address, 20) || len(log.Topics) > 4 {
				return nil, ErrInvalid
			}
			topics := make([]string, 0, len(log.Topics))
			for _, topic := range log.Topics {
				if !fixed(topic, 32) {
					return nil, ErrInvalid
				}
				topics = append(topics, strings.ToLower(topic))
			}
			data, err := describeHex(log.Data)
			if err != nil {
				return nil, err
			}
			logs = append(logs, Log{Address: strings.ToLower(log.Address), Topics: topics, Data: data})
		}
		annotation := Annotation{Status: "not-reported"}
		if !null(w.ValidatorChange) {
			annotation.Status = "unsupported"
			v := summary(w.ValidatorChange)
			annotation.Value = &v
		}
		result, errorName := outcome(w.Result)
		out = append(out, Operation{Number: w.Number, Tx: w.Tx, TxHash: strings.ToLower(w.TxHash), Path: path, From: strings.ToLower(w.From), Instance: strings.ToLower(w.Instance), Input: summary(input), Selector: selector, Call: contractCall(input), Effective: w.Effective, View: w.View, Result: result, ErrorName: errorName, ResultValue: summary([]byte(w.Result)), Logs: logs, Verified: w.Verified, ExecutingProposalID: w.ExecutingProposalID, ValidatorChange: annotation})
	}
	return out, nil
}

func history(raw json.RawMessage, key ProposalKey) (ProposalHistory, error) {
	var w struct {
		Instance string          `json:"instance"`
		ID       string          `json:"id"`
		Proposal json.RawMessage `json:"proposal"`
		Ops      json.RawMessage `json:"ops"`
	}
	if decode(raw, &w, "instance", "id", "ops") != nil || !strings.EqualFold(w.Instance, key.Instance) || w.ID != key.ID || len(w.Proposal) == 0 {
		return ProposalHistory{}, ErrInvalid
	}
	var p *Proposal
	if !null(w.Proposal) {
		value, err := proposal(w.Proposal)
		if err != nil || value.ID != key.ID {
			return ProposalHistory{}, ErrInvalid
		}
		p = &value
	}
	// A proposal response covers its full history and its current state,
	// independently of the bounded govOps request in the same capture.
	ops, err := operations(w.Ops, 0, ^uint64(0), key.Instance)
	if err != nil {
		return ProposalHistory{}, err
	}
	return ProposalHistory{Instance: strings.ToLower(w.Instance), ID: w.ID, Proposal: p, Ops: ops}, nil
}

func changes(raw json.RawMessage, from, to uint64) ([]ValidatorChange, error) {
	var rows []json.RawMessage
	if decode(raw, &rows) != nil || rows == nil || len(rows) > 1024 {
		return nil, ErrInvalid
	}
	out := make([]ValidatorChange, 0, len(rows))
	seen := map[string]bool{}
	for _, row := range rows {
		var w struct {
			Number     string          `json:"number"`
			Validators []string        `json:"validators"`
			Ops        json.RawMessage `json:"ops"`
			Epoch      json.RawMessage `json:"epoch"`
		}
		if decode(row, &w, "number", "ops") != nil || !within(w.Number, from, to) || seen[w.Number] {
			return nil, ErrInvalid
		}
		seen[w.Number] = true
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(row, &fields)
		validatorsReported := len(fields["validators"]) > 0 && !null(fields["validators"])
		vs, err := addresses(w.Validators, false)
		if err != nil {
			return nil, err
		}
		n, _ := uint64Of(w.Number)
		ops, err := operations(w.Ops, n, n, "")
		if err != nil {
			return nil, err
		}
		var epoch *Epoch
		if len(w.Epoch) > 0 && !null(w.Epoch) {
			var e struct {
				Candidates []string `json:"Candidates"`
				Validators []string `json:"Validators"`
				Added      []string `json:"Added"`
				Removed    []string `json:"Removed"`
				NoKey      []string `json:"NoKey"`
			}
			if decode(w.Epoch, &e) != nil || !hasFields(w.Epoch, "Candidates", "Validators", "Added", "Removed") {
				return nil, ErrInvalid
			}
			lists := make([][]string, 0, 5)
			for _, list := range [][]string{e.Candidates, e.Validators, e.Added, e.Removed, e.NoKey} {
				v, err := addresses(list, false)
				if err != nil {
					return nil, err
				}
				lists = append(lists, v)
			}
			epoch = &Epoch{Candidates: lists[0], Validators: lists[1], Added: lists[2], Removed: lists[3], NoKey: lists[4]}
		}
		out = append(out, ValidatorChange{Number: w.Number, Validators: vs, ValidatorsReported: validatorsReported, Ops: ops, Epoch: epoch})
	}
	return out, nil
}
