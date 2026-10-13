package reexec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/observe/journal"
)

func TestProtocolChild(t *testing.T) {
	mode := os.Args[len(os.Args)-1]
	if !strings.HasPrefix(mode, "answers_") && !strings.HasPrefix(mode, "warmup_") && mode != "valid" && mode != "oversize" && mode != "bad_id" && mode != "stall" && mode != "core" && mode != "env_error" && mode != "bad_writer" && mode != "generic_error" {
		return
	}
	if mode == "core" {
		if Serve(context.Background(), os.Stdin, os.Stdout) != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	decoder := json.NewDecoder(os.Stdin)
	var request map[string]any
	if decoder.Decode(&request) != nil {
		os.Exit(2)
	}
	if mode == "stall" {
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	if mode == "oversize" {
		_, _ = io.WriteString(os.Stdout, strings.Repeat("x", 100000)+"\n")
		os.Exit(0)
	}
	enc := json.NewEncoder(os.Stdout)
	features := []string{}
	if strings.HasPrefix(mode, "answers_") && mode != "answers_old" {
		features = append(features, "context_answers_v1")
	}
	if strings.HasPrefix(mode, "warmup_bounded_") && mode != "warmup_bounded_old" {
		features = append(features, "bounded_warmup_v1")
	}
	_ = enc.Encode(map[string]any{"type": "hello", "protocol": Protocol, "impl": "wbft", "version": strings.Repeat("a", 40), "features": features})
	if decoder.Decode(&request) != nil {
		os.Exit(2)
	}
	if strings.HasPrefix(mode, "answers_") {
		if request["answer_scope"] != "context" {
			os.Exit(2)
		}
		source := map[string]any{"writer_run": "synthetic-source", "engine_run": uint64(18446744073709551615), "step": uint64(1), "call": 1, "kind": int(inputlog.EnvIsBadBlock), "key": "0x" + strings.Repeat("d", 64)}
		if mode == "answers_bad_source" {
			source["step"] = 999
		}
		for i := 1; i <= 2; i++ {
			input := "timer"
			if i == 1 {
				input = "start"
			}
			var sources []any
			if i == 2 || mode == "answers_reuse" {
				sources = []any{source}
			}
			_ = enc.Encode(map[string]any{"type": "step", "id": 1, "writer_run": "synthetic-source", "engine_run": uint64(18446744073709551615), "step": i, "input": input, "out_digest": "0x" + strings.Repeat("b", 64), "match": true, "outputs": 0, "context_answers": mode != "answers_bad_flag", "answer_sources": sources})
		}
		_ = enc.Encode(map[string]any{"type": "done", "id": 1, "steps": 2, "mismatches": 0, "counterfactual": mode != "answers_bad_mode", "answer_scope": "context"})
		_ = decoder.Decode(&request)
		os.Exit(0)
	}
	if strings.HasPrefix(mode, "warmup_bounded_") {
		if request["warmup_from_height"] != float64(1) || request["compare_from_height"] != float64(3) {
			os.Exit(2)
		}
		bad := 0
		for i := 1; i <= 4; i++ {
			if i == 3 && mode == "warmup_bounded_env_error" {
				_ = enc.Encode(map[string]any{"type": "error", "id": 1, "code": "env_exhausted", "writer_run": "synthetic-source", "engine_run": uint64(18446744073709551615), "step": 3, "approximate": true})
				_ = decoder.Decode(&request)
				os.Exit(0)
			}
			approximate := i < 4
			prefix := i < 3
			if mode == "warmup_bounded_bad_marker" && i == 3 {
				approximate = false
			}
			match := mode != "warmup_bounded_suspect" || i != 3
			out := "0x" + strings.Repeat("b", 64)
			if !match {
				out = "0x" + strings.Repeat("c", 64)
				bad++
			}
			input, writer, step := "timer", "synthetic-source", i
			if i == 4 {
				input, writer, step = "start", "writer-reset", 1
			}
			_ = enc.Encode(map[string]any{"type": "step", "id": 1, "writer_run": writer, "engine_run": uint64(18446744073709551615), "step": step, "input": input, "out_digest": out, "match": match, "outputs": 0, "approximate": approximate, "warmup": prefix})
		}
		approx := 3
		if mode == "warmup_bounded_bad_count" {
			approx = 2
		}
		_ = enc.Encode(map[string]any{"type": "done", "id": 1, "steps": 4, "mismatches": bad, "approximate_steps": approx, "warmup_steps": 2})
		_ = decoder.Decode(&request)
		os.Exit(0)
	}
	if strings.HasPrefix(mode, "warmup_") {
		if mode == "warmup_error" {
			_ = enc.Encode(map[string]any{"type": "error", "id": 1, "code": "env_exhausted", "writer_run": "synthetic-source", "engine_run": uint64(18446744073709551615), "step": 1})
		} else {
			match, digest := true, "0x"+strings.Repeat("b", 64)
			if mode == "warmup_diverged" {
				match = false
				digest = "0x" + strings.Repeat("c", 64)
			}
			if mode == "warmup_bad_digest" {
				digest = "0x" + strings.Repeat("c", 64)
			}
			_ = enc.Encode(map[string]any{"type": "step", "id": 1, "writer_run": "synthetic-source", "engine_run": uint64(18446744073709551615), "step": 1, "input": "start", "out_digest": digest, "match": match, "outputs": 0})
			_ = enc.Encode(map[string]any{"type": "step", "id": 1, "writer_run": "synthetic-source", "engine_run": uint64(18446744073709551615), "step": 2, "input": "timer", "out_digest": "0x" + strings.Repeat("b", 64), "match": true, "outputs": 0})
			bad := 0
			if !match {
				bad = 1
			}
			_ = enc.Encode(map[string]any{"type": "done", "id": 1, "steps": 2, "mismatches": bad})
		}
		_ = decoder.Decode(&request)
		os.Exit(0)
	}
	if mode == "env_error" || mode == "generic_error" {
		code := "env_exhausted"
		if mode == "generic_error" {
			code = "replay_error"
		}
		_ = enc.Encode(map[string]any{"type": "error", "id": 1, "code": code, "writer_run": "synthetic-source", "engine_run": uint64(18446744073709551615), "step": 1})
		_ = decoder.Decode(&request)
		os.Exit(0)
	}
	id := 1
	if mode == "bad_id" {
		id = 2
	}
	writer := ""
	if mode == "bad_writer" {
		writer = "wrong-writer"
	}
	_ = enc.Encode(map[string]any{"writer_run": writer, "type": "step", "id": id, "engine_run": uint64(18446744073709551615), "step": 1, "input": "start", "out_digest": "0x" + strings.Repeat("b", 64), "match": true, "outputs": 0})
	_ = enc.Encode(map[string]any{"type": "done", "id": 1, "steps": 1, "mismatches": 0})
	_ = decoder.Decode(&request)
	os.Exit(0)
}
func testHelper(t *testing.T, mode string) Helper {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return Helper{Path: exe, Args: []string{"-test.run=^TestProtocolChild$", "--", mode}, Timeout: 10 * time.Second}
}
func TestHelperBoundsIdentityAndMissingHeight(t *testing.T) {
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "00000000000000000000.wal"), []byte("synthetic protocol source"), 0600); err != nil {
		t.Fatal(err)
	}
	in := messages.Input{ID: "journal", Kind: "journal", Path: source}
	sum, err := messages.Fingerprint(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	chain := filepath.Join(t.TempDir(), "chain.rlp")
	bytes := []byte("synthetic chain fingerprint")
	if err = os.WriteFile(chain, bytes, 0600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(bytes)
	p := Plan{Input: messages.Prepared{Input: in, Summary: sum}, Chain: chain, ChainSHA: hex.EncodeToString(hash[:]), SourceVersions: []string{strings.Repeat("a", 40)}, Heights: []Height{{Number: "1", Status: "complete", Steps: 1}}, Steps: []Step{{Ordinal: 2, Height: "1", Engine: "18446744073709551615", Number: "1", Input: "start", Recorded: "0x" + strings.Repeat("b", 64), Completeness: "complete"}}}
	var got []Step
	r, err := Execute(context.Background(), p, testHelper(t, "valid"), func(s Step) error { got = append(got, s); return nil })
	if err != nil || r.Status != "regression" || r.Matches != 1 || got[0].Engine != "18446744073709551615" {
		t.Fatal(r, got, err)
	}
	p.Steps[0].Run = "synthetic-source"
	got = nil
	failed, e := Execute(context.Background(), p, testHelper(t, "env_error"), func(s Step) error { got = append(got, s); return nil })
	if e == nil || failed.Issue != "env_exhausted" || len(got) != 1 || got[0].Class != "env_exhausted" || got[0].Run != "synthetic-source" || failed.FirstMismatch == nil || *failed.FirstMismatch != 2 {
		t.Fatal(failed, got, e)
	}

	got = nil
	generic, e := Execute(context.Background(), p, testHelper(t, "generic_error"), func(s Step) error { got = append(got, s); return nil })
	if e == nil || generic.Issue != "replay_error" || len(got) != 1 || got[0].Class != "not_comparable" || generic.Mismatches != 0 {
		t.Fatal("generic error falsely classified", generic, got, e)
	}
	if _, e = Execute(context.Background(), p, testHelper(t, "bad_writer"), func(Step) error { t.Fatal("wrong writer accepted"); return nil }); e == nil {
		t.Fatal("wrong writer accepted")
	}
	p.Heights = append(p.Heights, Height{Number: "2", Status: "not_possible", Issues: []string{"no_recorded_steps"}})
	r, err = Execute(context.Background(), p, testHelper(t, "valid"), func(Step) error { return nil })
	if err != nil || r.Status != "partial" {
		t.Fatal("missing requested height accepted", r, err)
	}
	for _, mode := range []string{"oversize", "bad_id", "stall"} {
		h := testHelper(t, mode)
		h.Timeout = 200 * time.Millisecond
		start := time.Now()
		_, err = Execute(context.Background(), p, h, func(Step) error { return nil })
		if err == nil || time.Since(start) > 3*time.Second {
			t.Fatal(mode, err, time.Since(start))
		}
	}
}

func simulationInput(t *testing.T) (messages.Prepared, string, string) {
	t.Helper()
	keys := make([]sim.Validator, 4)
	for i := range keys {
		var err error
		keys[i], err = sim.NewValidator(keccak.Sum256Bytes([]byte("closed-replay-test-" + strconv.Itoa(i))))
		if err != nil {
			t.Fatal(err)
		}
	}
	links := []sim.Link{}
	for i, a := range keys {
		for j, b := range keys {
			if i != j {
				links = append(links, sim.Link{From: a.Address(), To: b.Address(), Delay: []time.Duration{time.Duration((i+1)*13+(j+1)*2) * time.Millisecond}})
			}
		}
	}
	dir := t.TempDir()
	result, err := sim.Run(context.Background(), sim.Scenario{Name: "synthetic-closed-replay", Seed: 3, Validators: keys, Links: links, Until: sim.Stop{Height: 4, Duration: time.Minute}}, sim.Output{JournalDir: dir})
	if err != nil || len(result.Violations) != 0 {
		t.Fatal(result, err)
	}
	chain := filepath.Join(dir, "chain.rlp")
	for node, files := range result.Journals {
		path := filepath.Join(t.TempDir(), "journal")
		if err = os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		for name, data := range files {
			if err = os.WriteFile(filepath.Join(path, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		in := messages.Input{ID: "journal", Kind: "journal", Node: strings.ToLower(node.Hex()), Path: path}
		sum, e := messages.Fingerprint(context.Background(), in)
		if e != nil {
			t.Fatal(e)
		}
		return messages.Prepared{Input: in, Summary: sum}, chain, strings.ToLower(codec.BlockHash(result.Chain[0].Header).Hex())
	}
	t.Fatal("no journal")
	return messages.Prepared{}, "", ""
}
func TestRecordedCoreAndIndependentWireCompleteness(t *testing.T) {
	p, chain, genesis := simulationInput(t)
	ctx := context.Background()
	plan, err := Inspect(ctx, p, chain, "8282", genesis, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range plan.Heights {
		if row.Status != "complete" {
			t.Fatal(row)
		}
	}
	count := 0
	r, err := Execute(ctx, plan, testHelper(t, "core"), func(s Step) error {
		count++
		if s.Class != "match" {
			t.Error(s)
		}
		return nil
	})
	if err != nil || count == 0 || r.Mismatches != 0 || r.Status == "reproduced" && r.VersionStatus != "matched" {
		t.Fatal(r, count, err)
	}
	// Delete an authoritative received frame used by a nonempty recorded output.
	reader, e := journal.OpenReader(nil, p.Input.Path)
	if e != nil {
		t.Fatal(e)
	}
	var records []journal.Record
	for {
		rec, e := reader.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		records = append(records, rec)
	}
	seg := records[0].Body.(*journal.SegmentRec)
	empty, e := inputlog.OutDigest(nil)
	if e != nil {
		t.Fatal(e)
	}
	var capture uint64
	for _, rec := range records {
		if b, ok := rec.Body.(*journal.StepRec); ok && b.InputKind == inputlog.KindCapturedMessage && b.HeadNumber.String() == "0" && b.OutDigest != empty {
			capture, e = inputlog.CapturedReference(b.Input)
			if e != nil {
				t.Fatal(e)
			}
			break
		}
	}
	target := -1
	for i, rec := range records {
		if b, ok := rec.Body.(*journal.MsgRec); ok && b.Dir == journal.In && capture != 0 && b.Capture == capture {
			target = i
			break
		}
	}
	if target < 0 {
		t.Fatal("no processed captured message with recorded outputs")
	}
	rewrite := func(gap bool) messages.Prepared {
		dir := filepath.Join(t.TempDir(), "journal")
		w, e := journal.Open(journal.Options{Dir: dir, Synchronous: true}, seg.Identity)
		if e != nil {
			t.Fatal(e)
		}
		for i, rec := range records[1:] {
			if i+1 == target {
				if gap {
					w.Put(journal.Record{Body: &journal.GapRec{Dropped: 1}})
				}
				continue
			}
			w.Put(rec)
		}
		if e = w.Close(); e != nil {
			t.Fatal(e)
		}
		in := p.Input
		in.Path = dir
		sum, e := messages.Fingerprint(ctx, in)
		if e != nil {
			t.Fatal(e)
		}
		return messages.Prepared{Input: in, Summary: sum}
	}
	missing, err := Inspect(ctx, rewrite(false), chain, "8282", genesis, 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range missing.Steps {
		for _, issue := range s.Issues {
			if issue == "missing_capture" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("deleted wire input was ignored")
	}
	r, err = Execute(ctx, missing, testHelper(t, "core"), func(Step) error { return nil })
	if err == nil || r.Issue != "input_gap" || r.Mode != "closed" {
		t.Fatal("missing source accepted in closed mode", r, err)
	}
	h := testHelper(t, "core")
	h.OmitMissing = true
	var omitted []Step
	r, err = Execute(ctx, missing, h, func(s Step) error {
		if s.Omitted {
			omitted = append(omitted, s)
		}
		return nil
	})
	if len(omitted) != 1 || omitted[0].Capture != strconv.FormatUint(capture, 10) || omitted[0].Class != "output_diverged" || omitted[0].Replayed != strings.ToLower(empty.Hex()) || r.Mode != "counterfactual" || r.Status == "reproduced" || err != nil && r.Issue != "env_exhausted" {
		t.Fatal("intentional loss must expose the actual changed output", r, omitted, err)
	}
	gap, err := Inspect(ctx, rewrite(true), chain, "8282", genesis, 1, 3)
	if err != nil || gap.JournalIssue != "journal_gap" {
		t.Fatal(gap.JournalIssue, err)
	}
	r, err = Execute(ctx, gap, testHelper(t, "core"), func(Step) error { return nil })
	if err == nil || r.Status == "reproduced" || r.Issue != "input_gap" {
		t.Fatal(r, err)
	}
	archive := filepath.Join(t.TempDir(), "inputs")
	objects, err := messages.Archive(ctx, archive, []messages.Prepared{p})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := Snapshot(ctx, p.Summary, objects[p.Input.ID])
	if err != nil {
		t.Fatal(err)
	}
	_ = os.RemoveAll(snapshot)
	first := objects[p.Input.ID][0]
	if err = os.WriteFile(first.Path, make([]byte, first.Bytes), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Snapshot(ctx, p.Summary, objects[p.Input.ID]); err == nil {
		t.Fatal("corrupt retained source accepted")
	}
}
