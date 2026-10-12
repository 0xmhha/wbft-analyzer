package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/0xmhha/wbft-analyzer/internal/derive/baseline"
	"math/big"
	"sort"
)

var ErrBaseline = errors.New("invalid baseline selection")

// RoundBaseline compares observer claims over a common full-height range.
// Dataset/input hashes expose provenance and reject overlapping source copies.
func (s *Store) RoundBaseline(ctx context.Context, network int64, ids []int64, from, to, node string) (baseline.Summary, error) {
	a, ok := new(big.Int).SetString(from, 10)
	if !ok {
		return baseline.Summary{}, ErrBaseline
	}
	b, ok := new(big.Int).SetString(to, 10)
	if !ok || a.Sign() < 0 || b.Cmp(a) < 0 {
		return baseline.Summary{}, ErrBaseline
	}
	span := new(big.Int).Sub(b, a)
	span.Add(span, big.NewInt(1))
	if span.Cmp(big.NewInt(100000)) > 0 {
		return baseline.Summary{}, ErrBaseline
	}
	out := baseline.Summary{From: from, To: to, Expected: span.Int64(), Runs: []baseline.Run{}, Comparisons: []baseline.Comparison{}, Method: "per-node/profile claims deduplicated by height; rates use known claims; independent runs have equal weight; unbiased sample variance (n-1); missing/unknown are separate; no network-decision pooling"}
	datasets, err := s.Datasets(ctx, network)
	if err != nil {
		return out, err
	}
	available := map[int64]Dataset{}
	for _, d := range datasets {
		available[d.ID] = d
	}
	hashes := map[[3]string]int64{}
	for _, id := range ids {
		d, ok := available[id]
		if !ok || d.Kind != "run" || d.Status != "complete" {
			return out, ErrBaseline
		}
		run := baseline.Run{Dataset: id, Name: d.Name, Inputs: []baseline.Input{}, Observers: []baseline.Observer{}}
		inputs, err := s.LogInputs(ctx, id)
		if err != nil {
			return out, err
		}
		observers := map[[2]string]*baseline.Observer{}
		for _, in := range inputs {
			if node != "" && in.Node != node {
				continue
			}
			key := [3]string{in.Node, in.Profile, in.SHA256}
			if previous, ok := hashes[key]; ok && previous != id {
				return out, errors.Join(ErrBaseline, errors.New("selected runs reuse the same node/profile/source hash"))
			}
			hashes[key] = id
			run.Inputs = append(run.Inputs, baseline.Input{ID: in.ID, Node: in.Node, Profile: in.Profile, SHA256: in.SHA256})
			k := [2]string{in.Node, in.Profile}
			if observers[k] == nil {
				observers[k] = &baseline.Observer{Node: in.Node, Profile: in.Profile, Missing: out.Expected, Bins: []baseline.Bin{}}
			}
		}
		if len(observers) == 0 {
			return out, ErrBaseline
		}
		rows, err := s.pool.Query(ctx, `SELECT event FROM (SELECT DISTINCT ON (node,profile,height) event FROM (SELECT node,event->>'profile' profile,height,event,axis_ns,input_id,line FROM log_events WHERE dataset_id=$1 AND kind='NEW_HEAD' AND height BETWEEN $2::numeric AND $3::numeric AND ($4='' OR node=$4)) x ORDER BY node,profile,height,axis_ns DESC,input_id DESC,line DESC) claims`, id, from, to, node)
		if err != nil {
			return out, err
		}
		bins := map[[3]string]int64{}
		for rows.Next() {
			var raw []byte
			var x LogEvent
			if err = rows.Scan(&raw); err != nil {
				rows.Close()
				return out, err
			}
			if err = json.Unmarshal(raw, &x); err != nil {
				rows.Close()
				return out, err
			}
			o := observers[[2]string{x.Node, x.Profile}]
			if o == nil {
				rows.Close()
				return out, ErrBaseline
			}
			o.Missing--
			if x.Round == "" {
				o.Unknown++
			} else {
				o.Known++
				bins[[3]string{x.Node, x.Profile, x.Round}]++
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return out, err
		}
		for k, count := range bins {
			observers[[2]string{k[0], k[1]}].Bins = append(observers[[2]string{k[0], k[1]}].Bins, baseline.Bin{Round: k[2], Count: count})
		}
		keys := [][2]string{}
		for k := range observers {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i][0] != keys[j][0] {
				return keys[i][0] < keys[j][0]
			}
			return keys[i][1] < keys[j][1]
		})
		for _, k := range keys {
			o := observers[k]
			sort.Slice(o.Bins, func(i, j int) bool {
				a, _ := new(big.Int).SetString(o.Bins[i].Round, 10)
				b, _ := new(big.Int).SetString(o.Bins[j].Round, 10)
				return a.Cmp(b) < 0
			})
			run.Observers = append(run.Observers, *o)
		}
		out.Runs = append(out.Runs, run)
	}
	out.Comparisons = baseline.Compare(out.Runs)
	return out, nil
}
