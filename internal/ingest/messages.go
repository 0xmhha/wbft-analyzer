package ingest

import (
	"context"
	"errors"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/store"
)

type MessageResult struct {
	DatasetID int64                `json:"dataset_id"`
	NetworkID int64                `json:"network_id"`
	Records   int64                `json:"records"`
	Skipped   bool                 `json:"skipped"`
	Inputs    []store.MessageInput `json:"inputs"`
}

func Messages(ctx context.Context, s *store.Store, m messages.Manifest) (res MessageResult, err error) {
	plan, meta, e := messages.Prepare(ctx, m)
	if e != nil {
		return res, e
	}
	network := logs.SafeNetwork(m.Network)
	d, release, e := s.BeginMessages(ctx, store.NetworkKey{ChainID: network.ChainID, GenesisHash: network.GenesisHash, Name: network.Name}, m.Name, meta)
	if e != nil {
		return res, e
	}
	defer release()
	res.DatasetID = d.ID
	res.NetworkID = d.NetworkID
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		detail := ""
		if err != nil {
			detail = "message import incomplete; see local diagnostics"
		}
		if e := s.FinishRange(cleanup, d.ID, res.Records, detail); err == nil {
			err = e
		}
	}()
	if d.Status == "complete" {
		res.Records = d.Progress
		res.Skipped = true
		res.Inputs, err = s.MessageInputs(ctx, d.ID)
		return res, err
	}
	for _, p := range plan {
		if err = s.PutMessageInput(ctx, d.ID, p.Summary); err != nil {
			return res, err
		}
		batch := make([]messages.Record, 0, 500)
		flush := func() error {
			if len(batch) == 0 {
				return nil
			}
			e := s.PutMessageRecords(ctx, d.ID, batch, res.Records+int64(len(batch)))
			if e == nil {
				res.Records += int64(len(batch))
				batch = batch[:0]
			}
			return e
		}
		stats, e := messages.Read(ctx, p, m.Network.ChainID, m.Network.GenesisHash, func(r messages.Record) error {
			batch = append(batch, r)
			if len(batch) == cap(batch) {
				return flush()
			}
			return nil
		})
		// Preserve the readable prefix, even when the final record is damaged.
		if fe := flush(); fe != nil {
			return res, fe
		}
		if se := s.FinishMessageInput(ctx, d.ID, p.Input.ID, stats); se != nil {
			return res, se
		}
		res.Inputs = append(res.Inputs, store.MessageInput{Summary: p.Summary, Stats: stats})
		if e != nil {
			return res, e
		}
		sum, e := messages.Fingerprint(ctx, p.Input)
		if e != nil {
			return res, e
		}
		if sum.SHA256 != p.Summary.SHA256 {
			return res, errors.New("message input changed during import")
		}
	}
	return res, nil
}
