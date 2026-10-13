package store

import (
	"context"
	"encoding/json"
	"errors"
	derived "github.com/0xmhha/wbft-analyzer/internal/derive/messages"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	source "github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/jackc/pgx/v5"
)

// MessageAssociation assesses two fixed source snapshots without mutating
// either. Matching run names alone never authorizes mixed-source measurement.
func (s *Store) MessageAssociation(ctx context.Context, runID, messageID int64) (derived.AssociationProof, error) {
	var proof derived.AssociationProof
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var kindA, kindB, statusA, statusB string
		var netA, netB, progressA, progressB int64
		if e := tx.QueryRow(ctx, `SELECT kind,network_id,status,progress FROM datasets WHERE id=$1`, runID).Scan(&kindA, &netA, &statusA, &progressA); e != nil {
			return e
		}
		if e := tx.QueryRow(ctx, `SELECT kind,network_id,status,progress FROM datasets WHERE id=$1`, messageID).Scan(&kindB, &netB, &statusB, &progressB); e != nil {
			return e
		}
		if kindA != "run" || kindB != "messages" || netA != netB || statusA != "complete" || statusB != "complete" {
			return errors.New("association requires completed run/message sources on one network")
		}
		if progressA+progressB > 1000000 {
			return ErrPairSource
		}
		records := []source.Record{}
		events := []logs.Event{}
		rows, e := tx.Query(ctx, `SELECT record FROM message_records WHERE dataset_id=$1 ORDER BY input_id,file,ordinal`, messageID)
		if e != nil {
			return e
		}
		for rows.Next() {
			var b []byte
			var x source.Record
			if e = rows.Scan(&b); e != nil {
				rows.Close()
				return e
			}
			if e = json.Unmarshal(b, &x); e != nil {
				rows.Close()
				return e
			}
			records = append(records, x)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		if int64(len(records)) != progressB {
			return errors.New("message source count changed")
		}
		rows, e = tx.Query(ctx, `SELECT event FROM log_events WHERE dataset_id=$1 ORDER BY input_id,line`, runID)
		if e != nil {
			return e
		}
		for rows.Next() {
			var b []byte
			var x LogEvent
			if e = rows.Scan(&b); e != nil {
				rows.Close()
				return e
			}
			if e = json.Unmarshal(b, &x); e != nil {
				rows.Close()
				return e
			}
			r, e := normalized(x)
			if e != nil {
				rows.Close()
				return e
			}
			events = append(events, r)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		if int64(len(events)) != progressA {
			return errors.New("event source count changed")
		}
		proof = derived.VerifyAssociation(records, events)
		return nil
	})
	return proof, err
}

func readAssociationEvents(ctx context.Context, tx pgx.Tx, id int64) ([]logs.Event, error) {
	rows, e := tx.Query(ctx, `SELECT event FROM log_events WHERE dataset_id=$1 ORDER BY input_id,line`, id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	events := []logs.Event{}
	for rows.Next() {
		var b []byte
		var x LogEvent
		if e = rows.Scan(&b); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(b, &x); e != nil {
			return nil, e
		}
		r, e := normalized(x)
		if e != nil {
			return nil, e
		}
		events = append(events, r)
		if len(events) > 1000000 {
			return nil, ErrPairSource
		}
	}
	return events, rows.Err()
}

func readEventCoverage(ctx context.Context, tx pgx.Tx, id int64, status string) ([]PairCoverage, error) {
	rows, e := tx.Query(ctx, `SELECT input_id,kind,stats FROM log_inputs WHERE dataset_id=$1 ORDER BY input_id`, id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []PairCoverage{}
	for rows.Next() {
		c := PairCoverage{DatasetID: id}
		var b []byte
		var stats logs.Stats
		if e = rows.Scan(&c.Input, &c.Kind, &b); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(b, &stats); e != nil {
			return nil, e
		}
		c.SequenceGaps = stats.SequenceGaps
		if stats.Lines > 0 || status == "complete" {
			wall := stats.ClockRegressions
			c.WallRegressions = &wall
			if c.Kind == "events" {
				mono := stats.MonotonicRegressions
				c.MonotonicRegressions = &mono
			}
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
