package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/reexec"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/jackc/pgx/v5"
)

// ReexecEventEvidence is a fresh, read-only association assessment. It does
// not change replay completeness or the stored output comparison.
type ReexecEventEvidence struct {
	Status  string     `json:"status"`
	Reason  string     `json:"reason,omitempty"`
	Dataset int64      `json:"event_dataset_id"`
	Ordinal int64      `json:"source_ordinal"`
	Events  []LogEvent `json:"events"`
}

// ReexecEvents uses one snapshot for the retained source, association proof,
// and selected events. Missing engine identity is never inferred here.
func (s *Store) ReexecEvents(ctx context.Context, dataset, id, ordinal, eventDataset int64) (ReexecEventEvidence, error) {
	out := ReexecEventEvidence{Status: "unavailable", Dataset: eventDataset, Ordinal: ordinal, Events: []LogEvent{}}
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var input string
		var summaryRaw, stepRaw, inputRaw, sourceRaw []byte
		err := tx.QueryRow(ctx, `SELECT r.input_id,r.summary,s.record FROM reexec_runs r JOIN reexec_steps s ON s.run_id=r.id WHERE r.dataset_id=$1 AND r.id=$2 AND s.ordinal=$3`, dataset, id, ordinal).Scan(&input, &summaryRaw, &stepRaw)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		var summary reexec.Result
		var step reexec.Step
		if err = json.Unmarshal(summaryRaw, &summary); err != nil {
			return err
		}
		if err = json.Unmarshal(stepRaw, &step); err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `SELECT i.summary,m.record FROM message_inputs i JOIN message_records m ON m.dataset_id=i.dataset_id AND m.input_id=i.input_id WHERE i.dataset_id=$1 AND i.input_id=$2 AND m.file=$3 AND m.ordinal=$4`, dataset, input, step.File, ordinal).Scan(&inputRaw, &sourceRaw)
		if errors.Is(err, pgx.ErrNoRows) {
			out.Reason = "source_unavailable"
			return nil
		}
		if err != nil {
			return err
		}
		var source messages.Record
		var original messages.Summary
		if err = json.Unmarshal(inputRaw, &original); err != nil {
			return err
		}
		if err = json.Unmarshal(sourceRaw, &source); err != nil {
			return err
		}
		if summary.SourceSHA == "" || summary.SourceSHA != original.SHA256 || source.Type != "step" || source.Run != step.Run || source.EngineRun != step.Engine || source.Step != step.Number || step.Engine == "" || step.Engine == "0" {
			out.Reason = "source_identity_mismatch"
			return nil
		}
		var sameNetwork bool
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM datasets a JOIN datasets b ON b.network_id=a.network_id WHERE a.id=$1 AND b.id=$2 AND b.kind='run' AND a.status='complete' AND b.status='complete')`, dataset, eventDataset).Scan(&sameNetwork)
		if err != nil {
			return err
		}
		if !sameNetwork {
			out.Reason = "event_source_unavailable"
			return nil
		}
		proof, err := messageAssociation(ctx, tx, eventDataset, dataset)
		if err != nil {
			return err
		}
		if proof.Status != "matched" {
			out.Reason = "association_" + proof.Status
			return nil
		}
		anchored := false
		for _, a := range proof.Anchors {
			if a.Status == "matched" && strings.EqualFold(a.Node, source.Node) && a.Run == step.Run && a.EngineRun == step.Engine {
				anchored = true
				break
			}
		}
		if !anchored {
			out.Reason = "engine_not_anchored"
			return nil
		}
		rows, err := tx.Query(ctx, `SELECT e.event FROM log_events e JOIN log_inputs i ON i.dataset_id=e.dataset_id AND i.input_id=e.input_id WHERE e.dataset_id=$1 AND i.kind='events' AND lower(e.node)=lower($2) AND e.event->>'source'='event' AND e.event->>'run'=$3 AND e.event->'fields'->>'engine_run'=$4 AND e.event->'fields'->>'step'=$5 ORDER BY e.input_id,e.line LIMIT 1001`, eventDataset, source.Node, step.Run, step.Engine, step.Number)
		if err != nil {
			return err
		}
		events, err := collect(rows, func(r pgx.CollectableRow) (LogEvent, error) {
			var e LogEvent
			var b []byte
			err := r.Scan(&b)
			if err == nil {
				err = json.Unmarshal(b, &e)
			}
			return e, err
		})
		if err != nil {
			return err
		}
		if len(events) > 1000 {
			return ErrPairSource
		}
		if len(events) == 0 {
			out.Reason = "no_explicit_step_events"
			return nil
		}
		// A repeated copy has competing original pointers. Preserve ambiguity;
		// never select whichever file happens to sort first.
		owner := events[0].Input
		for _, e := range events {
			if e.Input != owner {
				out.Reason = "ambiguous_event_input"
				return nil
			}
		}
		out.Status = "matched"
		out.Events = events
		return nil
	})
	return out, err
}
