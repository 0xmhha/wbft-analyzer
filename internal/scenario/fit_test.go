package scenario

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	measuredOptions := o
	measuredOptions.WireMetric = pairs.WriteStartToReadComplete
	measured, err := Fit(context.Background(), measuredOptions)
	if err != nil || measured.WireMetric != pairs.WriteStartToReadComplete || measured.SourceSHA256 == got.SourceSHA256 || measured.Provenance.ModelSHA256 == got.Provenance.ModelSHA256 || measured.Scenario != nil {
		t.Fatal("measurement definition lost from immutable model identity", measured, err)
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
	o.TransportInputs = []string{"b", "a"}
	selected, err := Fit(context.Background(), o)
	if err != nil || len(selected.TransportInputs) != 2 || selected.TransportInputs[0].ID != "a" || len(selected.Provenance.Inputs) != 3 || selected.SourceSHA256 == withFrames.SourceSHA256 || selected.Provenance.ModelSHA256 == withFrames.Provenance.ModelSHA256 || selected.Scenario != nil {
		t.Fatal("transport choice lost source evidence or model identity", selected, err)
	}
	o.TransportInputs = []string{"absent"}
	if _, err := Fit(context.Background(), o); err == nil {
		t.Fatal("unknown transport source accepted")
	}
	o.TransportInputs = nil
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
	// The full capture continues beyond the comparison range. Preserve every
	// original event while excluding the later unfinished build from this fit.
	for _, raw := range res.Events {
		var first struct {
			Node string `json:"node"`
		}
		if err := json.Unmarshal(bytes.SplitN(raw, []byte("\n"), 2)[0], &first); err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(raw)
		input, err := InspectEvents(context.Background(), Input{ID: "events-" + first.Node[2:], Kind: "events", Node: first.Node, SHA256: hex.EncodeToString(hash[:])}, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		o.Events = append(o.Events, input)
	}
	before, err := json.Marshal(o.Events)
	if err != nil {
		t.Fatal(err)
	}
	scoped, err := Fit(context.Background(), o)
	if err != nil || scoped.App.Unproved != 0 || scoped.Scope.AppExcluded == 0 || scoped.Model.Status != "partial" || scoped.Scenario != nil {
		t.Fatal("range tail or missing-node evidence misclassified", scoped.Model, scoped.Scope, scoped.App.Unproved, err)
	}
	after, err := json.Marshal(o.Events)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("fitting changed original event evidence", err)
	}
}
