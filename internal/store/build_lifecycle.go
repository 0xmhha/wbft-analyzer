package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/jackc/pgx/v5"
)

// BuildLifecycle retains exact source candidates. Complete refers to observed
// application call boundaries, not proposal acceptance or simulator support.
type BuildLifecycle struct {
	State      string     `json:"state"`
	BuildID    string     `json:"build_id"`
	Status     string     `json:"status"`
	Origin     LogEvent   `json:"origin"`
	Events     []LogEvent `json:"events"`
	AssemblyNS *string    `json:"assembly_ns"`
}

func buildFields(x LogEvent) map[string]string {
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(x.Fields, &fields)
	out := map[string]string{}
	for _, key := range []string{"build_id", "number", "status", "hash"} {
		var s string
		if json.Unmarshal(fields[key], &s) == nil {
			out[key] = s
		}
	}
	return out
}
func buildKind(k event.Kind) bool {
	return k == event.BuildHandover || k == event.BuildStarted || k == event.BuildFinished
}
func projectBuildLifecycle(out *BuildLifecycle, complete bool) {
	kinds := map[event.Kind][]LogEvent{}
	for _, x := range out.Events {
		if x.Source != "event" || x.Profile != logs.EventProfile || x.Node != out.Origin.Node || x.Input != out.Origin.Input || x.Run != out.Origin.Run || buildFields(x)["build_id"] != out.BuildID || x.Height != buildFields(x)["number"] {
			return
		}
		kinds[x.Kind] = append(kinds[x.Kind], x)
	}
	if len(kinds[event.BuildHandover]) > 1 || len(kinds[event.BuildStarted]) > 1 || len(kinds[event.BuildFinished]) > 1 {
		out.State = "ambiguous"
		return
	}
	if len(kinds[event.BuildHandover]) != 1 || len(kinds[event.BuildFinished]) != 1 {
		return
	}
	h, f := kinds[event.BuildHandover][0], kinds[event.BuildFinished][0]
	if h.Height == "" || h.Round == "" || h.Height != f.Height || h.Round != f.Round || h.Line >= f.Line {
		return
	}
	hm, e1 := monoOf(h)
	fm, e2 := monoOf(f)
	if e1 != nil || e2 != nil || fm < hm {
		return
	}
	out.Status = buildFields(f)["status"]
	if out.Status == "submitted" {
		hash := buildFields(f)["hash"]
		if !strings.HasPrefix(hash, "0x") || len(hash) != 66 {
			return
		}
		if _, err := hex.DecodeString(hash[2:]); err != nil {
			return
		}
	}
	if len(kinds[event.BuildStarted]) == 1 {
		s := kinds[event.BuildStarted][0]
		sm, e := monoOf(s)
		if e != nil || s.Height != h.Height || s.Round != h.Round || s.Line <= h.Line || s.Line >= f.Line || sm < hm || sm > fm {
			return
		}
		if out.Status == "submitted" && complete {
			delta := strconv.FormatInt(fm-sm, 10)
			out.AssemblyNS = &delta
		}
	} else if out.Status == "submitted" {
		return
	}
	switch out.Status {
	case "submitted", "replaced", "height_left", "stopped", "unavailable", "head_changed", "failed":
	default:
		return
	}
	if complete {
		out.State = "complete"
	}
}
func monoOf(x LogEvent) (int64, error) {
	if x.Mono == nil {
		return 0, errors.New("build monotonic clock unavailable")
	}
	n, err := strconv.ParseInt(*x.Mono, 10, 64)
	if err != nil || n < 0 {
		return 0, errors.New("invalid build monotonic clock")
	}
	return n, nil
}

// BuildSource reads all candidates for one explicit input/node/run/build ID in
// one database snapshot. It never chooses a nearby timestamp or another input.
func (s *Store) BuildSource(ctx context.Context, dataset int64, input string, line int64) (BuildLifecycle, error) {
	out := BuildLifecycle{State: "incomplete", Events: []LogEvent{}}
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var raw []byte
		var status, inputKind string
		var statsRaw []byte
		err := tx.QueryRow(ctx, `SELECT e.event,d.status,i.kind,i.stats FROM log_events e JOIN datasets d ON d.id=e.dataset_id JOIN log_inputs i ON i.dataset_id=e.dataset_id AND i.input_id=e.input_id WHERE e.dataset_id=$1 AND e.input_id=$2 AND e.line=$3`, dataset, input, line).Scan(&raw, &status, &inputKind, &statsRaw)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if err = json.Unmarshal(raw, &out.Origin); err != nil {
			return err
		}
		out.BuildID = buildFields(out.Origin)["build_id"]
		id := strings.TrimPrefix(out.BuildID, "build-")
		n, parse := strconv.ParseUint(id, 10, 64)
		if out.Origin.Source != "event" || out.Origin.Profile != logs.EventProfile || !buildKind(out.Origin.Kind) || parse != nil || n == 0 || out.BuildID != "build-"+strconv.FormatUint(n, 10) {
			out.State = "unavailable"
			return nil
		}
		rows, err := tx.Query(ctx, `SELECT event FROM log_events WHERE dataset_id=$1 AND input_id=$2 AND node=$3 AND run=$4 AND kind IN ('BUILD_HANDOVER','BUILD_STARTED','BUILD_FINISHED') AND event->'fields'->>'build_id'=$5 ORDER BY line LIMIT 65`, dataset, input, out.Origin.Node, out.Origin.Run, out.BuildID)
		if err != nil {
			return err
		}
		out.Events, err = collect(rows, func(row pgx.CollectableRow) (LogEvent, error) {
			var x LogEvent
			var b []byte
			e := row.Scan(&b)
			if e == nil {
				e = json.Unmarshal(b, &x)
			}
			return x, e
		})
		if err != nil {
			return err
		}
		if len(out.Events) > 64 {
			return errors.New("build source candidate limit exceeded")
		}
		var stats logs.Stats
		if err := json.Unmarshal(statsRaw, &stats); err != nil {
			return err
		}
		projectBuildLifecycle(&out, status == "complete" && inputKind == "events" && stats.Malformed == 0 && stats.Unknown == 0 && stats.SequenceGaps == 0)
		return nil
	})
	return out, err
}
