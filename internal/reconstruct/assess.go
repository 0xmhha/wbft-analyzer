package reconstruct

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/source/runtimeobs"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/observe/event"
)

// Assess verifies every supplied source before returning any projection.
// It identifies available witnesses, not reconstructed inputs: processing
// order, application answers and exact core inputs still require binding.
func Assess(ctx context.Context, m Manifest, from, to string) (Assessment, error) {
	out, err := assess(ctx, m, from, to)
	if err != nil {
		return Assessment{}, err
	}
	return out, nil
}

func assess(ctx context.Context, m Manifest, from, to string) (Assessment, error) {
	out := Assessment{Version: Version, Phase: "source_readiness", Node: m.Node, ChainID: m.Network.ChainID, GenesisHash: m.Network.GenesisHash, From: from, To: to}
	if !validManifest(m) {
		return out, errors.New("invalid reconstruction identity or source")
	}
	var index map[string]int
	var err error
	out.Heights, index, err = heightRange(from, to)
	if err != nil {
		return out, err
	}
	add := func(height, kind string, point Point) {
		if i, ok := index[height]; ok {
			recordEvidence(&out.Heights[i], kind, point)
		}
	}
	raw, err := snapshot(ctx, m.Log, 256<<20)
	if err != nil {
		return out, err
	}
	profile, err := logs.LoadProfile("gstable@740526d03")
	if err != nil {
		return out, err
	}
	out.Sources.LogSHA, out.Sources.LogBytes = m.Log.SHA256, int64(len(raw))
	out.Sources.LogProfile, out.Sources.LogProfileSHA, out.Sources.LogNormalizer = profile.ID, profile.SHA256, logs.NormalizerVersion
	processing := newProcessing(m, index)
	cursor := bufio.NewScanner(bytes.NewReader(raw))
	cursor.Buffer(make([]byte, 64<<10), 4<<20)
	var cursorLine int64
	out.Sources.LogStats, err = logs.Read(ctx, bytes.NewReader(raw), profile, m.Node, "log", func(e logs.Event) error {
		for cursorLine < e.Line {
			if !cursor.Scan() {
				return errors.New("reconstruction log coordinates unavailable")
			}
			cursorLine++
		}
		if err := processing.log(e, cursor.Bytes()); err != nil {
			return err
		}
		if e.Record.Kind == event.EngineStart {
			if address, ok := e.Record.Fields["address"].(string); ok && !strings.EqualFold(address, m.Node) {
				return errors.New("reconstruction log node identity mismatch")
			}
		}
		if e.Record.View == nil {
			return nil
		}
		kind := "log_event"
		if e.Level == "trace" && e.Record.Kind == event.TimerArm {
			kind = "timer_arm_log"
		}
		add(e.Record.View.Seq, kind, Point{Kind: kind, File: "log", Line: e.Line, Run: e.Run, ViewInferred: e.ViewInferred})
		return nil
	})
	if err != nil {
		return out, err
	}
	if m.Frames != nil {
		input := messages.Input{ID: "frames", Kind: "frames", Node: m.Node, Path: m.Frames.Path, SHA256: m.Frames.SHA256}
		prepared, _, err := messages.Prepare(ctx, messages.Manifest{Format: messages.Format, Name: "reconstruction", Network: m.Network, Clock: messages.Clock{Model: "unknown"}, Inputs: []messages.Input{input}})
		if err != nil {
			return out, err
		}
		if prepared[0].Summary.Bytes > 512<<20 {
			return out, errors.New("reconstruction frames exceed 512MiB")
		}
		stats, err := messages.Read(ctx, prepared[0], m.Network.ChainID, m.Network.GenesisHash, func(r messages.Record) error {
			if err := processing.frame(r); err != nil {
				return err
			}
			if r.Type == "frame" && r.Dir == "in" && r.Decode == "decoded" {
				kind := "received_frame"
				if r.Peer == "" {
					kind = "received_frame_unknown_peer"
				}
				add(r.Height, kind, Point{Kind: kind, File: r.File, Line: r.Ordinal, Run: r.Run, Sequence: r.Seq})
			}
			return nil
		})
		if err != nil {
			return out, errors.New("reconstruction frame input refused")
		}
		final, err := messages.Fingerprint(ctx, input)
		if err != nil || final.SHA256 != prepared[0].Summary.SHA256 {
			return out, errors.New("reconstruction frame source changed")
		}
		out.Sources.Frames, out.Sources.FrameStats = &prepared[0].Summary, &stats
		out.Sources.FrameNormalizer = messages.Normalizer
	}
	if m.Runtime != nil {
		raw, err := snapshot(ctx, *m.Runtime, 128<<20)
		if err != nil {
			return out, err
		}
		capture, err := runtimeobs.FromReader(bytes.NewReader(raw))
		if err != nil || capture.Node != m.Node {
			return out, errors.New("reconstruction runtime identity or source refused")
		}
		out.Sources.RuntimeSHA = m.Runtime.SHA256
		out.Sources.RuntimeNormalizer = capture.Normalizer
		for _, engine := range capture.Engines {
			for _, candidate := range engine.Configs {
				if candidate.Config != nil {
					add(candidate.Config.Height, "startup_config_candidate", Point{Kind: "startup_config_candidate", File: "runtime", Line: int64(candidate.Line), Run: capture.Run, Sequence: candidate.Seq})
				}
			}
		}
	}
	if m.Chain != nil {
		raw, err := snapshot(ctx, *m.Chain, 128<<20)
		if err != nil {
			return out, err
		}
		blocks, err := sim.DecodeChain(raw)
		if err != nil || len(blocks) == 0 || blocks[0] == nil || blocks[0].Header == nil || strings.ToLower(codec.BlockHash(blocks[0].Header).Hex()) != m.Network.GenesisHash {
			return out, errors.New("reconstruction canonical chain identity mismatch")
		}
		for i, block := range blocks {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			if block == nil || block.Header == nil || !block.Header.Number.IsUint64() || block.Header.Number.Big().Uint64() != uint64(i) || i > 0 && block.Header.ParentHash != codec.BlockHash(blocks[i-1].Header) {
				return out, errors.New("reconstruction chain is not consecutive and parent-linked")
			}
			add(strconv.Itoa(i), "canonical_block", Point{Kind: "canonical_block", File: "chain", BlockIndex: strconv.Itoa(i)})
		}
		out.Sources.ChainSHA = m.Chain.SHA256
	}
	for i := range out.Heights {
		h := &out.Heights[i]
		if count(*h, "received_frame") == 0 {
			h.Issues = append(h.Issues, "received_message_source_unavailable")
		}
		if count(*h, "timer_arm_log") == 0 {
			h.Issues = append(h.Issues, "timer_source_unavailable")
		}
		if len(h.Issues) == 0 {
			h.Status = "partial"
		}
		if count(*h, "canonical_block") == 0 {
			h.Issues = append(h.Issues, "canonical_block_unavailable")
		}
		if count(*h, "startup_config_candidate") == 0 {
			h.Issues = append(h.Issues, "startup_configuration_unavailable")
		}
		// These are unresolved bindings, not claims that no source exists.
		h.Issues = append(h.Issues, "source_run_association_unbound", "processing_order_unbound", "application_answers_unbound", "proposal_request_unbound", "head_delivery_unbound", "validator_context_unbound", "core_inputs_not_reconstructed")
		if out.Sources.LogStats.Malformed != 0 || out.Sources.LogStats.Unknown != 0 || out.Sources.LogStats.ClockRegressions != 0 {
			h.Issues = append(h.Issues, "log_diagnostics_require_review")
		}
		if stats := out.Sources.FrameStats; stats != nil && (stats.GapRecords != 0 || stats.SequenceGaps != 0 || stats.PartialRuns != 0 || stats.ClockRegressions != 0) {
			h.Issues = append(h.Issues, "frame_capture_incomplete")
		}
		if stats := out.Sources.FrameStats; stats != nil && stats.Undecoded != 0 {
			h.Issues = append(h.Issues, "unlocated_frames_require_review")
		}
		sort.Slice(h.Evidence, func(i, j int) bool { return h.Evidence[i].Kind < h.Evidence[j].Kind })
	}
	if err := processing.finish(ctx, m, &out); err != nil {
		return out, err
	}
	return out, nil
}

func recordEvidence(h *Height, kind string, point Point) {
	for i := range h.Evidence {
		if h.Evidence[i].Kind == kind {
			h.Evidence[i].Count++
			if len(h.Evidence[i].Examples) < 4 {
				h.Evidence[i].Examples = append(h.Evidence[i].Examples, point)
			}
			return
		}
	}
	h.Evidence = append(h.Evidence, Evidence{Kind: kind, Count: 1, Examples: []Point{point}})
}

func count(h Height, kind string) int64 {
	for _, e := range h.Evidence {
		if e.Kind == kind {
			return e.Count
		}
	}
	return 0
}
