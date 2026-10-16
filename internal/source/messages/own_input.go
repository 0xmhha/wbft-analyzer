package messages

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
)

var errOwnFrameProvenance = errors.New("invalid accepted own-input provenance")

// OwnSourcePoint addresses a retained metadata record, not raw payload bytes.
type OwnSourcePoint struct {
	Input   string `json:"input"`
	File    string `json:"file"`
	Ordinal int64  `json:"ordinal"`
	Seq     string `json:"seq"`
}

type JournalPosition struct {
	Segment string `json:"segment"`
	Offset  string `json:"offset"`
}

// OwnInputEvidence identifies accepted own bytes. It does not identify a
// particular asynchronous send call or prove delivery to a peer.
type OwnInputEvidence struct {
	Outcome   OwnSourcePoint  `json:"outcome"`
	Input     OwnSourcePoint  `json:"input"`
	EngineRun string          `json:"engine_run"`
	Step      string          `json:"step"`
	Journal   JournalPosition `json:"journal_position"`
}

func ownPoint(r Record) OwnSourcePoint { return OwnSourcePoint{r.Input, r.File, r.Ordinal, r.Seq} }

type ownScope struct{ input, file, node, run string }
type ownRecordKey struct {
	ownScope
	seq string
}

func ownKey(r Record) ownRecordKey {
	return ownRecordKey{ownScope{r.Input, r.File, r.Node, r.Run}, r.Seq}
}

// The spool contains only closed normalized metadata. Validate all source
// references before emitting own evidence; legacy damaged input still retains
// its readable prefix. Payload bytes never enter the spool.
func readFrames(ctx context.Context, p Prepared, emit func(Record) error) (Stats, error) {
	spool, err := os.CreateTemp("", "wbft-frame-provenance-*")
	if err != nil {
		return Stats{}, errors.New("cannot create frame metadata spool")
	}
	defer func() { _ = spool.Close(); _ = os.Remove(spool.Name()) }()
	selected := map[ownRecordKey]Record{}
	lost := map[ownScope]bool{}
	identities := map[string]string{}
	conflicted := false
	var schedulerRows []Record
	var cacheRows []*cacheRawRecord
	sawCache := false
	enc := json.NewEncoder(spool)
	stats, readErr := readFramesRaw(ctx, p, func(r Record) error {
		if r.cacheRaw != nil {
			cacheRows = append(cacheRows, r.cacheRaw)
			sawCache = sawCache || r.cacheRaw.hasCache()
		}
		if err := enc.Encode(r); err != nil {
			return errors.New("cannot spool frame metadata")
		}
		if r.Scheduler != nil || r.Timer != nil || r.Type == "scheduler_step" || r.Type == "own_input" {
			schedulerRows = append(schedulerRows, r)
		}
		scope := ownKey(r).ownScope
		if previous, ok := identities[r.File]; ok && previous != r.Run {
			conflicted = true
		} else {
			identities[r.File] = r.Run
		}
		if r.Type == "gap" {
			lost[scope] = true
		}
		if r.Type == "own_input" || r.InputOf != "" || r.OwnMessageOf != "" {
			selected[ownKey(r)] = r
		}
		return nil
	})
	if readErr != nil && (len(selected) > 0 || errors.Is(readErr, errOwnFrameProvenance) || errors.Is(readErr, errSchedulerFrameSource) || len(schedulerRows) > 0 || sawCache || errors.Is(readErr, errCacheFrameSource)) {
		return Stats{}, readErr
	}
	if err := validateSchedulerFrames(schedulerRows, lost, conflicted); err != nil {
		return Stats{}, err
	}
	cacheProofs, err := cacheFrameProofs(cacheRows)
	if err != nil {
		return Stats{}, err
	}
	proofs, err := ownProofs(selected, lost, conflicted)
	if err != nil {
		return Stats{}, err
	}
	if len(selected) > 0 || len(schedulerRows) > 0 || sawCache {
		if p.Summary.SHA256 == "" {
			return Stats{}, errors.New("frame evidence requires source fingerprints")
		}
		for _, f := range p.Summary.Files {
			if frameName.MatchString(f.Name) && f.SHA256 == "" {
				return Stats{}, errors.New("frame evidence requires file fingerprints")
			}
		}
	}
	if _, err = spool.Seek(0, io.SeekStart); err != nil {
		return Stats{}, errors.New("cannot rewind frame metadata")
	}
	decoder := json.NewDecoder(spool)
	for {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		var r Record
		err := decoder.Decode(&r)
		if err == io.EOF {
			break
		}
		if err != nil {
			return Stats{}, errors.New("cannot read frame metadata spool")
		}
		r.OwnInput = proofs[ownKey(r)]
		r.CacheEvidence = cacheProofs[ownKey(r)]
		if err = emit(r); err != nil {
			return stats, err
		}
	}
	return stats, readErr
}

func ownProofs(records map[ownRecordKey]Record, lost map[ownScope]bool, conflicted bool) (map[ownRecordKey]*OwnInputEvidence, error) {
	result := map[ownRecordKey]*OwnInputEvidence{}
	if len(records) == 0 {
		return result, nil
	}
	fail := func() (map[ownRecordKey]*OwnInputEvidence, error) {
		return nil, errOwnFrameProvenance
	}
	if conflicted {
		return fail()
	}
	inputs := map[ownRecordKey]Record{}
	users := map[ownRecordKey]int{}
	type messageKey struct {
		ownScope
		phase, key string
	}
	counts := map[messageKey]int{}
	generations := map[struct {
		ownScope
		engine, step string
	}]bool{}
	positions := map[struct {
		ownScope
		segment, offset string
	}]bool{}
	for k, r := range records {
		if lost[k.ownScope] {
			return fail()
		}
		if r.InputOf != "" && r.Type != "outcome" || r.OwnMessageOf != "" && r.Type != "frame" {
			return fail()
		}
		if r.Type == "own_input" {
			if r.Via != "internal" || r.InputKind != "message" || r.Peer != r.Node || r.Decode != "decoded" || r.Signature != "recovered" || r.Signer != r.Node || r.Key == "" || r.Phase == "" || r.Size == nil || r.Journal == nil || !positiveDecimal(r.EngineRun) || !positiveDecimal(r.Step) || !positiveDecimal(r.Seq) || !positiveDecimal(r.Journal.Offset) {
				return fail()
			}
			if _, err := strconv.ParseUint(r.Journal.Segment, 10, 64); err != nil {
				return fail()
			}
			g := struct {
				ownScope
				engine, step string
			}{k.ownScope, r.EngineRun, r.Step}
			pos := struct {
				ownScope
				segment, offset string
			}{k.ownScope, r.Journal.Segment, r.Journal.Offset}
			if generations[g] || positions[pos] {
				return fail()
			}
			generations[g], positions[pos] = true, true
			inputs[k] = r
			counts[messageKey{k.ownScope, r.Phase, r.Key}]++
		}
	}
	for k, r := range records {
		if r.InputOf == "" {
			continue
		}
		target := ownRecordKey{k.ownScope, r.InputOf}
		i, ok := inputs[target]
		a, e1 := strconv.ParseUint(r.Seq, 10, 64)
		b, e2 := strconv.ParseUint(i.Seq, 10, 64)
		if !ok || e1 != nil || e2 != nil || a >= b || r.Type != "outcome" || r.Of != "" || r.Via != "self" || r.Outcome != "ACCEPT" || r.Check != "PROCESS" || r.Peer != r.Node || r.EngineRun != i.EngineRun || r.Step != i.Step || r.Phase != i.Phase || r.Key != i.Key {
			return fail()
		}
		users[target]++
		proof := &OwnInputEvidence{Outcome: ownPoint(r), Input: ownPoint(i), EngineRun: i.EngineRun, Step: i.Step, Journal: *i.Journal}
		result[k], result[target] = proof, proof
	}
	for k := range inputs {
		if users[k] != 1 {
			return fail()
		}
	}
	for k, r := range records {
		if r.OwnMessageOf == "" {
			continue
		}
		proof := result[ownRecordKey{k.ownScope, r.OwnMessageOf}]
		if proof == nil || r.Type != "frame" || r.Dir != "out" || r.Cause != "relay" || r.RelayOf != "" {
			return fail()
		}
		i := inputs[ownRecordKey{k.ownScope, proof.Input.Seq}]
		if counts[messageKey{k.ownScope, r.Phase, r.Key}] != 1 || r.PayloadSHA256 != i.PayloadSHA256 || r.Phase != i.Phase || r.Key != i.Key || r.Size == nil || i.Size == nil || *r.Size != *i.Size || r.Decode != "decoded" || r.Signature != "recovered" || r.Signer != r.Node {
			return fail()
		}
		result[k] = proof
	}
	return result, nil
}

func positiveDecimal(s string) bool {
	n, err := strconv.ParseUint(s, 10, 64)
	return err == nil && n != 0 && number(n) == s
}
