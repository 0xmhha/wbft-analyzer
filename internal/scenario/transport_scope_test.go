package scenario

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

func TestRecordingGapRequiresNodeShutdownInsteadOfEnginePause(t *testing.T) {
	node := "0x" + strings.Repeat("1", 40)
	rows, origin := engineHistoryFixture(t, node)
	hash := strings.Repeat("a", 64)
	input := EventInput{Source: Input{ID: "native", Node: node, Kind: "events", SHA256: hash}, Stats: logs.Stats{SHA256: hash}, Records: rows}
	from, to := origin, origin.Add(65*time.Millisecond)
	if _, _, err := nativeWindow(node, from, to, []EventInput{input}); err != nil {
		t.Fatal("closed process window rejected", err)
	}
	rows[4].Record.Kind = event.EngineStop
	if _, _, err := nativeWindow(node, from, to, []EventInput{input}); err == nil {
		t.Fatal("engine pause licensed a process recording gap")
	}
}

func transportDocument(t *testing.T, id, kind, node string, value any) EvidenceDocument {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return EvidenceDocument{Source: Input{ID: id, Kind: kind, Node: node, SHA256: hex.EncodeToString(sum[:])}, Bytes: raw}
}
func transportFixture(t *testing.T) (TransportEvidence, []MessageInput, []*types.Block, []string, time.Time) {
	t.Helper()
	nodes, links := completeFixture()
	sc, err := Build(nodes, links, sim.Params{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 100}, []time.Duration{0}, []time.Duration{0}, sim.Stop{Height: 2, Duration: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	result, err := sim.Run(context.Background(), sc, sim.Output{})
	if err != nil {
		t.Fatal(err)
	}
	origin := sim.Epoch
	addresses := []string{}
	for _, v := range sc.Validators {
		addresses = append(addresses, strings.ToLower(v.Address().Hex()))
	}
	evidence := TransportEvidence{Declaration: Input{ID: "transport-declaration", Kind: "transport-manifest", Node: "network", SHA256: strings.Repeat("a", 64)}}
	headers := []map[string]any{}
	for i, b := range result.Chain {
		headers = append(headers, map[string]any{"number": fmt.Sprintf("0x%x", i), "hash": strings.ToLower(codec.BlockHash(b.Header).Hex())})
	}
	ctl := map[string]any{"format": "wbft-local-takeover-case/1", "status": "recording_windows_verified", "addresses": addresses, "nodes_stopped": true, "verified_heights": map[string]any{"first": 0, "last": 2, "all_node_hashes_equal": true}, "phases": []any{map[string]any{"name": "captured", "at": origin.Add(3 * time.Second), "heads": []int{2, 2, 2, 2}}}}
	launches := []any{}
	exits := []int{}
	inputs := []MessageInput{}
	payload := []byte{0xc0}
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	for i, node := range addresses {
		inputID := fmt.Sprintf("wire-%d", i)
		run := fmt.Sprintf("tap-%d-%d", 100+i, origin.UnixNano())
		dir := t.TempDir()
		name := "frames-" + run + ".jsonl"
		if err := os.MkdirAll(filepath.Join(dir, "payloads", digest[:2]), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "payloads", digest[:2], digest), payload, 0600); err != nil {
			t.Fatal(err)
		}
		rows := []map[string]any{}
		add := func(peer, kind string, at time.Duration) map[string]any {
			r := map[string]any{"v": 1, "type": kind, "node": node, "run": run, "seq": len(rows), "t_wall": origin.Add(at).Format(time.RFC3339Nano), "t_mono_ns": int64(2*time.Second) + int64(len(rows)), "peer": peer}
			rows = append(rows, r)
			return r
		}
		for _, peer := range addresses {
			if peer == node {
				continue
			}
			r := add(peer, "conn", 100*time.Millisecond)
			r["event"] = "istanbul_attached"
			for _, direction := range []string{"out", "in"} {
				r := add(peer, "frame", 300*time.Millisecond)
				r["dir"], r["code"], r["size"], r["payload_sha256"], r["payload_source"] = direction, "0x11", len(payload), digest, "consumed"
				if direction == "out" {
					r["write_result"] = "ok"
				}
				r["io"] = map[string]any{"start_wall": origin.Add(200 * time.Millisecond).Format(time.RFC3339Nano), "end_wall": origin.Add(250 * time.Millisecond).Format(time.RFC3339Nano), "start_mono_ns": 200000000, "end_mono_ns": 250000000}
			}
			r = add(peer, "conn", 3500*time.Millisecond)
			r["event"] = "closed"
		}
		file, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		enc := json.NewEncoder(file)
		for _, r := range rows {
			if err := enc.Encode(r); err != nil {
				t.Fatal(err)
			}
		}
		if err = file.Close(); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(raw)
		input := messages.Input{ID: inputID, Kind: "frames", Node: node, Path: dir}
		summary, err := messages.Fingerprint(context.Background(), input)
		if err != nil {
			t.Fatal(err)
		}
		in, err := InspectMessageSnapshot(context.Background(), messages.Prepared{Input: input, Summary: summary}, "1", codec.BlockHash(result.Chain[0].Header).Hex())
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, in)
		cert := map[string]any{"format": "wbft-transport-recording-window/1", "scope": "recording_window_only", "node": node, "run": run, "start_wall": origin, "end_wall": origin.Add(4 * time.Second), "frame_sha256": hex.EncodeToString(hash[:]), "recording_complete": true, "writer_success": true, "delivery_coverage_proven": false, "frame_attempts": fmt.Sprint(len(rows)), "frame_dropped": "0", "frame_incomplete": "0", "streams_active": "0", "pending_reads": "0", "pending_writes": "0", "streams_opened": "3", "streams_closed": "3"}
		evidence.Windows = append(evidence.Windows, TransportWindowEvidence{Input: inputID, Certificate: transportDocument(t, fmt.Sprintf("certificate-%d", i), "transport-certificate", node, cert)})
		evidence.Headers = append(evidence.Headers, transportDocument(t, fmt.Sprintf("headers-%d", i), "transport-headers", node, headers))
		launches = append(launches, map[string]any{"at": origin, "node": i, "pid": 100 + i, "kind": "legacy", "instrumentation_env": map[string]any{"WBFT_TAP_NODE": node}})
		exits = append(exits, 0)
	}
	ctl["launches"], ctl["process_exit_codes"] = launches, exits
	evidence.Controller = transportDocument(t, "controller", "transport-controller", "network", ctl)
	return evidence, inputs, result.Chain, addresses, origin
}

func TestClosedTransportScopeBindsRawStreamsAndIndependentCutoff(t *testing.T) {
	e, in, blocks, nodes, origin := transportFixture(t)
	scope, coverage, err := BindTransportScope(e, in, nil, blocks, nodes, origin, 10*time.Second)
	if err != nil || len(coverage) != 4 || len(scope.Sessions) != 12 || scope.PhysicalDeliveryProven || len(scope.Sources) != 10 {
		t.Fatal(scope, len(coverage), err)
	}
	for _, c := range coverage {
		if !c.Complete || !c.SettledThrough.Equal(origin.Add(3*time.Second)) || !c.To.Equal(origin.Add(4*time.Second)) {
			t.Fatal("last receipt substituted for controller cutoff", c)
		}
	}
	options := []Node{}
	for _, node := range nodes {
		var address types.Address
		if err := address.UnmarshalText([]byte(node)); err != nil {
			t.Fatal(err)
		}
		options = append(options, Node{Address: address})
	}
	sc := sim.Scenario{Validators: make([]sim.Validator, 0), Until: sim.Stop{Height: 2, Duration: 10 * time.Second}}
	keys, err := TestValidators([]types.Address{options[0].Address, options[1].Address, options[2].Address, options[3].Address})
	if err != nil {
		t.Fatal(err)
	}
	sc.Validators = keys
	prepared, err := ApplyTransportSessions(sc, options, scope, origin)
	if err != nil || len(prepared.Partitions) != 24 {
		t.Fatal("startup and shutdown gaps omitted", len(prepared.Partitions), err)
	}
}

func TestClosedTransportScopeRejectsContradictoryEvidence(t *testing.T) {
	for _, name := range []string{"failed_exit", "missing_exit", "future_cutoff", "physical_claim", "unclosed_stream", "dropped_records", "missing_counter", "changed_header", "wrong_frame_hash", "source_tamper", "sequence_gap", "missing_native_lifecycle", "duplicate_writer", "unknown_field", "duplicate_json_key"} {
		t.Run(name, func(t *testing.T) {
			e, in, blocks, nodes, origin := transportFixture(t)
			edit := func(doc *EvidenceDocument, key string, value any) {
				var m map[string]any
				if err := json.Unmarshal(doc.Bytes, &m); err != nil {
					t.Fatal(err)
				}
				m[key] = value
				*doc = transportDocument(t, doc.Source.ID, doc.Source.Kind, doc.Source.Node, m)
			}
			switch name {
			case "failed_exit":
				edit(&e.Controller, "process_exit_codes", []int{1, 0, 0, 0})
			case "missing_exit":
				edit(&e.Controller, "process_exit_codes", []any{nil, 0, 0, 0})
			case "future_cutoff":
				edit(&e.Controller, "phases", []any{map[string]any{"name": "captured", "at": origin.Add(5 * time.Second), "heads": []int{2, 2, 2, 2}}})
			case "physical_claim":
				edit(&e.Windows[0].Certificate, "delivery_coverage_proven", true)
			case "unclosed_stream":
				edit(&e.Windows[0].Certificate, "streams_active", "1")
			case "dropped_records":
				edit(&e.Windows[0].Certificate, "frame_dropped", "1")
			case "missing_counter":
				edit(&e.Windows[0].Certificate, "pending_reads", nil)
			case "changed_header":
				e.Headers[0] = transportDocument(t, e.Headers[0].Source.ID, "transport-headers", nodes[0], []any{map[string]any{"number": "0x0", "hash": strings.Repeat("0", 64)}})
			case "wrong_frame_hash":
				edit(&e.Windows[0].Certificate, "frame_sha256", strings.Repeat("b", 64))
			case "source_tamper":
				e.Controller.Bytes = append(e.Controller.Bytes, ' ')
			case "sequence_gap":
				in[0].Records[1].Seq = "7"
			case "missing_native_lifecycle":
				var c map[string]any
				_ = json.Unmarshal(e.Controller.Bytes, &c)
				c["launches"].([]any)[0].(map[string]any)["kind"] = "native"
				e.Controller = transportDocument(t, "controller", "transport-controller", "network", c)
			case "duplicate_writer":
				e.Windows[1] = e.Windows[0]
			case "unknown_field":
				edit(&e.Windows[0].Certificate, "unrecognized_proof", true)
			case "duplicate_json_key":
				e.Controller.Bytes = []byte(`{"format":"x","format":"wbft-local-takeover-case/1"}`)
				sum := sha256.Sum256(e.Controller.Bytes)
				e.Controller.Source.SHA256 = hex.EncodeToString(sum[:])
			}
			if _, _, err := BindTransportScope(e, in, nil, blocks, nodes, origin, 10*time.Second); err == nil {
				t.Fatal("contradictory scope accepted", name)
			}
		})
	}
}
