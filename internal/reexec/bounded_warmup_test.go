package reexec

import (
	"context"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
	"io"
	"path/filepath"
	"strconv"
	"testing"
)

func boundedProtocolPlan(t *testing.T) Plan {
	p := warmupPlan(t)
	p.From, p.To = 3, 4
	p.Heights = []Height{{Number: "3", Status: "not_possible", Issues: []string{"missing_engine_start"}}, {Number: "4", Status: "complete"}}
	first := p.Steps[0]
	p.Steps = nil
	for i := 1; i <= 4; i++ {
		s := first
		s.Ordinal, s.Number, s.Height, s.Input = int64(i+10), strconv.Itoa(i), strconv.Itoa(i), "timer"
		s.Completeness, s.Issues = "not_possible", []string{"missing_engine_start"}
		if i == 4 {
			s.Run, s.Number, s.Input, s.Completeness, s.Issues = "writer-reset", "1", "start", "complete", []string{}
		}
		p.Steps = append(p.Steps, s)
	}
	return p
}

func TestBoundedWarmupCannotEstablishReproduction(t *testing.T) {
	for _, mode := range []string{"warmup_bounded_match", "warmup_bounded_suspect"} {
		t.Run(mode, func(t *testing.T) {
			p := boundedProtocolPlan(t)
			p.Steps[3].Height = "3"
			h := testHelper(t, mode)
			h.WarmupHeights = 2
			var selected []Step
			r, err := Execute(context.Background(), p, h, func(s Step) error { selected = append(selected, s); return nil })
			if err != nil || r.Status != "partial" || r.Issue != "approximate_state" || r.Mismatches != 0 || r.FirstMismatch != nil || len(selected) != 2 {
				t.Fatal(r, selected, err)
			}
			if !selected[0].Approximate || selected[0].Warmup || selected[1].Approximate || selected[1].Class != "match" {
				t.Fatal(selected)
			}
			if r.Warmup == nil || r.Warmup.Policy != "bounded" || r.Warmup.Status != "approximate" || r.Warmup.Steps != 2 || r.Warmup.FromHeight != "1" || r.Warmup.CompareFromHeight != "3" {
				t.Fatal(r.Warmup)
			}
			if mode == "warmup_bounded_suspect" && (r.WarmupSuspect != 1 || selected[0].Class != "warmup_suspect" || r.Matches != 1) {
				t.Fatal(r, selected)
			}
			if mode == "warmup_bounded_match" && (r.WarmupSuspect != 0 || r.Matches != 2) {
				t.Fatal(r)
			}
		})
	}
}

func TestBoundedWarmupProtocolGuards(t *testing.T) {
	for _, mode := range []string{"warmup_bounded_old", "warmup_bounded_bad_marker", "warmup_bounded_bad_count"} {
		t.Run(mode, func(t *testing.T) {
			h := testHelper(t, mode)
			h.WarmupHeights = 2
			r, err := Execute(context.Background(), boundedProtocolPlan(t), h, func(Step) error { return nil })
			if err == nil || r.Status == "reproduced" {
				t.Fatal(r, err)
			}
			if mode == "warmup_bounded_old" && r.Issue != "warmup_unsupported" {
				t.Fatal(r)
			}
		})
	}
}

func TestOfficialBoundedWarmupPreservesSourceCompleteness(t *testing.T) {
	p, chain, genesis := simulationInput(t)
	ctx := context.Background()
	reader, err := journal.OpenReader(nil, p.Input.Path)
	if err != nil {
		t.Fatal(err)
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
	rewrite := func(badHead bool) messages.Prepared {
		dir := filepath.Join(t.TempDir(), "journal")
		writer, e := journal.Open(journal.Options{Dir: dir, Synchronous: true}, seg.Identity)
		if e != nil {
			t.Fatal(e)
		}
		changed := false
		for _, rec := range records[1:] {
			if b, ok := rec.Body.(*journal.StepRec); ok {
				if b.InputKind == inputlog.KindStart {
					continue
				}
				if badHead && !changed {
					clone := *b
					clone.HeadHash = types.Hash{}
					rec.Body = &clone
					changed = true
				}
			}
			writer.Put(rec)
		}
		if e = writer.Close(); e != nil {
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
	plan, err := Inspect(ctx, rewrite(false), chain, "8282", genesis, 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	h := testHelper(t, "core")
	h.WarmupHeights = 2
	var steps []Step
	result, err := Execute(ctx, plan, h, func(s Step) error { steps = append(steps, s); return nil })
	if err != nil || result.Status != "partial" || result.Issue != "approximate_state" || len(steps) == 0 {
		t.Fatal(result, err)
	}
	for _, s := range steps {
		if !s.Approximate || s.Completeness == "complete" {
			t.Fatal("fabricated closed state", s)
		}
	}
	h.WarmupHeights = 0
	result, err = Execute(ctx, plan, h, func(Step) error { t.Fatal("no-start source replayed without warmup"); return nil })
	if err != nil || result.Status != "not_possible" || result.Total != 0 {
		t.Fatal(result, err)
	}
	plan, err = Inspect(ctx, rewrite(true), chain, "8282", genesis, 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	h.WarmupHeights = 2
	result, err = Execute(ctx, plan, h, func(Step) error { t.Fatal("inconsistent head executed"); return nil })
	if err == nil || result.Issue != "head_identity" {
		t.Fatal(result, err)
	}
}

func TestApproximateApplicationFailureIsNotAnExactMismatch(t *testing.T) {
	h := testHelper(t, "warmup_bounded_env_error")
	h.WarmupHeights = 2
	var selected []Step
	r, err := Execute(context.Background(), boundedProtocolPlan(t), h, func(s Step) error { selected = append(selected, s); return nil })
	if err == nil || r.Status != "failed" || r.Issue != "env_exhausted" || r.Mismatches != 0 || r.WarmupSuspect != 1 || r.FirstMismatch != nil || len(selected) != 1 || selected[0].Class != "warmup_suspect" || !selected[0].Approximate {
		t.Fatal(r, selected, err)
	}
}
