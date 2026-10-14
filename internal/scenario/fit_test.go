package scenario

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pairs "github.com/0xmhha/wbft-analyzer/internal/derive/messages"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/sim"
)

func TestFitPreservesPartialSourceWithoutDefaultingMissingNodes(t *testing.T) {
	nodes, links := completeFixture()
	d := []time.Duration{time.Millisecond}
	sc, err := Build(nodes, links, sim.Params{RequestTimeoutSeconds: 2, BlockPeriodSeconds: 1, EpochLength: 100}, d, d, sim.Stop{Height: 6, Duration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	journals, events := t.TempDir(), t.TempDir()
	res, err := sim.Run(context.Background(), sc, sim.Output{JournalDir: journals, EventsDir: events})
	if err != nil {
		t.Fatal(err)
	}
	chain, err := os.ReadFile(filepath.Join(journals, "chain.rlp"))
	if err != nil {
		t.Fatal(err)
	}
	o := FitOptions{Dataset: 1, Chain: chain, Origin: sim.Epoch, Clock: pairs.Clock{Model: "shared-host"}, From: 1, To: 5, Until: time.Minute, CoreCommit: strings.Repeat("b", 40), Seeds: []int64{1, 2}, Journals: []messages.Prepared{}}
	// Two nodes of a four-node chain are deliberately absent from this source.
	for i, v := range sc.Validators[:2] {
		node := strings.ToLower(v.Address().Hex())
		input := messages.Input{ID: string(rune('a' + i)), Kind: "journal", Node: node, Path: filepath.Join(journals, hex.EncodeToString(v.Address().Bytes()))}
		summary, err := messages.Fingerprint(context.Background(), input)
		if err != nil {
			t.Fatal(err)
		}
		o.Journals = append(o.Journals, messages.Prepared{Input: input, Summary: summary})
	}
	got, err := Fit(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if got.Model.Status != "partial" || got.Scenario != nil || len(got.Model.Issues) == 0 || got.SourceSHA256 == "" {
		t.Fatalf("partial fit %+v", got)
	}
	if len(got.Recorded) != 5 || got.Recorded[0].Number != 1 {
		t.Fatal("canonical recorded range missing")
	}
	for _, h := range got.Recorded {
		child, err := codec.DecodeExtra(res.Chain[h.Number+1].Header)
		if err != nil || h.Round != uint64(child.PrevRound) {
			t.Fatal("wrong recorded round")
		}
	}
	framesDir := t.TempDir()
	frameNode := strings.ToLower(sc.Validators[2].Address().Hex())
	frame := `{"v":1,"type":"frame","node":"` + frameNode + `","run":"synthetic-frame","seq":1,"t_wall":"2020-01-01T00:00:00Z","t_mono_ns":0,"dir":"in","code":"0x13","size":0}` + "\n"
	if err := os.WriteFile(filepath.Join(framesDir, "frames-synthetic.jsonl"), []byte(frame), 0600); err != nil {
		t.Fatal(err)
	}
	frameInput := messages.Input{ID: "wire-source", Kind: "frames", Node: frameNode, Path: framesDir}
	frameSummary, err := messages.Fingerprint(context.Background(), frameInput)
	if err != nil {
		t.Fatal(err)
	}
	o.Frames = []messages.Prepared{{Input: frameInput, Summary: frameSummary}}
	withFrames, err := Fit(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	foundFrame := false
	for _, in := range withFrames.Provenance.Inputs {
		if in.ID == "wire-source" && in.Kind == "frames" && in.SHA256 == frameSummary.SHA256 {
			foundFrame = true
		}
	}
	if !foundFrame || withFrames.SourceSHA256 == got.SourceSHA256 || withFrames.Model.Status != "partial" || withFrames.Scenario != nil {
		t.Fatal("frame source omitted or missing runtime/options inferred")
	}
	o.Frames = nil
	o.Runtime = []Node{{Address: sc.Validators[0].Address(), RuntimeEvidence: "verified", ReplayWAL: true}}
	if _, err := Fit(context.Background(), o); err == nil {
		t.Fatal("caller assertion proved runtime policy")
	}
	o.Runtime = nil
	first := got.SourceSHA256
	o.Clock.SkewMS = 1
	other, err := Fit(context.Background(), o)
	if err != nil || other.SourceSHA256 == first {
		t.Fatal("clock model change not pinned", err)
	}
	if bytes.Contains([]byte(other.SourceSHA256), []byte(journals)) {
		t.Fatal("local path crossed provenance boundary")
	}
}
