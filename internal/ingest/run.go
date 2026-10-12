package ingest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/events"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

type RunResult struct {
	DatasetID, NetworkID, Events int64
	Inputs                       []store.LogInput
	Skipped                      bool
	Elapsed                      time.Duration
}

func Run(ctx context.Context, s *store.Store, m logs.Manifest, progress func(int64)) (res RunResult, err error) {
	plan, err := logs.Prepare(ctx, m)
	if err != nil {
		return res, err
	}
	n := logs.SafeNetwork(m.Network)
	d, release, err := s.BeginRun(ctx, store.NetworkKey{ChainID: n.ChainID, GenesisHash: n.GenesisHash, Name: n.Name}, m.Name, plan.Metadata)
	if err != nil {
		return res, err
	}
	defer release()
	res.DatasetID, res.NetworkID = d.ID, d.NetworkID
	start := time.Now()
	detail := ""
	defer func() {
		res.Elapsed = time.Since(start)
		if err != nil && detail == "" {
			detail = "run import failed; see local command output"
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if e := s.FinishRange(cleanup, d.ID, res.Events, detail); err == nil {
			err = e
		}
	}()
	if d.Status == "complete" {
		res.Skipped = true
		res.Events = d.Progress
		res.Inputs, err = s.LogInputs(ctx, d.ID)
		if err == nil {
			_, err = s.RebuildReplay(ctx, d.ID)
		}
		return res, err
	}
	diagnostics := []string{}
	for _, in := range plan.Inputs {
		if err = s.PutLogInput(ctx, d.ID, in.Summary); err != nil {
			return res, err
		}
		f, e := os.Open(in.Path)
		if e != nil {
			err = e
			return res, err
		}
		batch := make([]logs.Event, 0, 500)
		flush := func() error {
			if len(batch) == 0 {
				return nil
			}
			if e := s.PutLogEvents(ctx, d.ID, batch, res.Events+int64(len(batch))); e != nil {
				return e
			}
			res.Events += int64(len(batch))
			batch = batch[:0]
			if progress != nil {
				progress(res.Events)
			}
			return nil
		}
		emit := func(ev logs.Event) error {
			if plan.Includes(ev.Wall) {
				batch = append(batch, ev)
				if len(batch) == cap(batch) {
					return flush()
				}
			}
			return nil
		}
		var stats logs.Stats
		if in.Summary.Kind == "events" {
			stats, e = events.Read(ctx, io.NewSectionReader(f, 0, in.Summary.Bytes), in.Summary.Node, in.Summary.ID, emit)
		} else {
			stats, e = logs.Read(ctx, io.NewSectionReader(f, 0, in.Summary.Bytes), in.Profile, in.Summary.Node, in.Summary.ID, emit)
		}
		f.Close()
		if e == nil {
			e = flush()
		}
		if e == nil && stats.SHA256 != in.Summary.SHA256 {
			e = errors.New("input changed during normalization")
		}
		if e != nil {
			err = e
			return res, err
		}
		if err = s.FinishLogInput(ctx, d.ID, in.Summary.ID, stats); err != nil {
			return res, err
		}
		res.Inputs = append(res.Inputs, store.LogInputOf(in.Summary, stats))
		if msg := stats.Diagnostic(); msg != "" {
			diagnostics = append(diagnostics, fmt.Sprintf("%s: %s", in.Summary.ID, msg))
		}
	}
	if len(diagnostics) > 0 {
		detail = strings.Join(diagnostics, "; ")
		err = errors.New(detail)
	}
	if err == nil {
		_, err = s.RebuildReplay(ctx, d.ID)
	}
	return res, err
}
