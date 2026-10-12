package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/0xmhha/wbft-analyzer/internal/reports"
	"github.com/jackc/pgx/v5"
)

type LogEvidence struct {
	Report       string    `json:"report"`
	Observation  string    `json:"observation"`
	Index        int       `json:"index"`
	Status       string    `json:"status"` // matched, network_mismatch, source_unavailable, ambiguous_source, event_unavailable, pointer_mismatch
	ReportInput  string    `json:"report_input"`
	DatasetInput string    `json:"dataset_input"`
	SHA256       string    `json:"sha256"`
	Line         int64     `json:"line"`
	Event        *LogEvent `json:"event"`
}

func (s *Store) ResolveLogEvidence(ctx context.Context, dataset int64, report, observation string, index int) (LogEvidence, error) {
	out := LogEvidence{Report: report, Observation: observation, Index: index, Status: "source_unavailable"}
	if index < 0 {
		return out, ErrNotFound
	}
	var same bool
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT coalesce(r.network_id=d.network_id,false),o.evidence->($4::int) FROM reports r JOIN observations o ON o.report_id=r.id JOIN datasets d ON d.id=$1 WHERE r.id=$2 AND o.obs_id=$3`, dataset, report, observation, index).Scan(&same, &raw)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && len(raw) == 0 {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if !same {
		out.Status = "network_mismatch"
		return out, nil
	}
	var p reports.Evidence
	if err = json.Unmarshal(raw, &p); err != nil {
		return out, err
	}
	out.ReportInput, out.Line = p.Input, p.Line
	if (p.Kind != "log" && p.Kind != "event") || p.Line < 1 || p.Input == "" {
		return out, nil
	}
	var in ReportInput
	err = s.pool.QueryRow(ctx, `SELECT input_id,kind,node,sha256,profile FROM report_inputs WHERE report_id=$1 AND input_id=$2`, report, p.Input).Scan(&in.ID, &in.Kind, &in.Node, &in.SHA256, &in.Profile)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if in.Kind != "log" || in.Node == "" || in.SHA256 == "" || p.Node != "" && p.Node != in.Node {
		out.Status = "pointer_mismatch"
		return out, nil
	}
	out.SHA256 = in.SHA256
	rows, err := s.pool.Query(ctx, `SELECT input_id FROM log_inputs WHERE dataset_id=$1 AND sha256=$2 AND node=$3 AND ($4='' OR profile=$4) ORDER BY input_id LIMIT 2`, dataset, in.SHA256, in.Node, in.Profile)
	if err != nil {
		return out, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return out, err
	}
	if len(ids) == 0 {
		return out, nil
	}
	if len(ids) > 1 {
		out.Status = "ambiguous_source"
		return out, nil
	}
	out.DatasetInput = ids[0]
	e, err := s.LogEvent(ctx, dataset, ids[0], p.Line)
	if errors.Is(err, ErrNotFound) {
		out.Status = "event_unavailable"
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if e.Node != in.Node || p.Number != "" && p.Number != e.Height {
		out.Status = "pointer_mismatch"
		return out, nil
	}
	out.Status = "matched"
	out.Event = &e
	return out, nil
}

func (s *Store) ReportInputs(ctx context.Context, report string) ([]ReportInput, error) {
	rows, err := s.pool.Query(ctx, `SELECT input_id,kind,node,sha256,profile FROM report_inputs WHERE report_id=$1 ORDER BY input_id`, report)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r pgx.CollectableRow) (ReportInput, error) {
		var in ReportInput
		err := r.Scan(&in.ID, &in.Kind, &in.Node, &in.SHA256, &in.Profile)
		return in, err
	})
}
