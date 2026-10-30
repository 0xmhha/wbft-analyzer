package messages

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/0xmhha/wbft-analyzer/internal/source/domainprofile"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

// ErrReceiveFailureSource requires original source inspection instead of projection.
var ErrReceiveFailureSource = errors.New("receive failure sources require the dedicated source check")

// ErrRetrySource distinguishes a new retry source from a legacy cache trace.
var ErrRetrySource = errors.New("round-change retry sources require the dedicated source check")

// ErrValidatorStartRestoreSource preserves an explicitly unavailable restore profile.
var ErrValidatorStartRestoreSource = errors.New("validator-start restore requires an unavailable independent model")

// Application queue metadata needs a separate runtime model.
var errAppQueueSource = errors.New("application queue sources require an explicit runtime model")
var errInboxSource = errors.New("inbox sources require an explicit runtime model")
var errInternalSource = errors.New("internal input sources require an explicit runtime model")
var errSelectionSource = errors.New("input selection sources require an explicit runtime model")
var errReceiveDispatchSource = errors.New("receive dispatch sources require an explicit runtime model")
var errWALReadSource = errors.New("WAL read sources require an explicit runtime model")
var errRestoreSource = errors.New("restore sources require an explicit runtime model")
var errSignerSource = errors.New("signer sources require an explicit runtime model")
var errSignerCallSource = errors.New("signer call sources require an explicit runtime model")
var errRuntimeSource = errors.New("runtime return sources require an explicit runtime model")
var errApplicationSource = errors.New("application execution sources require an explicit runtime model")
var errFinalizeSource = errors.New("application finalization sources require an explicit runtime model")

type journalCacheState struct {
	run      string
	versions map[string]uint64
	peers    map[uint32]string
	indices  map[string]uint32
}

func newJournalCacheState() *journalCacheState {
	return &journalCacheState{versions: map[string]uint64{}}
}
func cacheBool(v bool) *bool { return &v }
func cacheAddresses(in []types.Address) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = strings.ToLower(v.Hex())
	}
	return out
}
func (s *journalCacheState) project(r *Record, rec journal.Record) error {
	if segment, ok := rec.Body.(*journal.SegmentRec); ok && segment.Core.ReceiveFailureCache != nil {
		return ErrReceiveFailureSource
	}
	switch rec.Body.(type) {
	case *journal.ReceiveFailureCacheRec, *journal.InboxFailureHitRec:
		return ErrReceiveFailureSource
	}
	if segment, ok := rec.Body.(*journal.SegmentRec); ok && segment.Core.RoundChangeRetry != nil {
		return ErrRetrySource
	}
	if cache, ok := rec.Body.(*journal.CacheRec); ok && cache.Retry.Version != 0 {
		return ErrRetrySource
	}
	if write, ok := rec.Body.(*journal.WriteCacheRec); ok && write.Transition.Retry.Version != 0 {
		return ErrRetrySource
	}

	if m, ok := rec.Body.(*journal.MsgRec); ok && (m.Session != nil || m.WriteAttempt != nil) {
		return errCacheFrameSource
	}
	switch rec.Body.(type) {
	case *journal.InternalRec:
		return errInternalSource
	case *journal.WALReadRec:
		return errWALReadSource
	case *journal.RestoreRec:
		return errRestoreSource
	case *journal.SignerRec:
		return errSignerSource
	case *journal.RuntimeRec:
		return errRuntimeSource
	case *journal.ApplicationRec:
		return errApplicationSource
	case *journal.SignerCallRec:
		return errSignerCallSource
	case *journal.ReceiveDispatchRec:
		return errReceiveDispatchSource
	case *journal.SelectionRec:
		return errSelectionSource
	case *journal.InboxRec:
		return errInboxSource
	case *journal.FinalizeRec:
		return errFinalizeSource
	case *journal.AppQueueRec:
		return errAppQueueSource
	case *journal.WriteCacheRec, *journal.ReceiveCacheRec, *journal.SessionRec, *journal.CoreStepRec:
		return errCacheFrameSource
	}
	first := false
	if b, ok := rec.Body.(*journal.SegmentRec); ok {
		// The legacy trace proves read-loop/before-send mutations. It cannot
		// prove a different accepted-input/completed-write runtime policy.
		if b.Core.CachePolicy != nil {
			return errCacheFrameSource
		}
		old, seen := s.versions[b.Run]
		if b.Core.CacheTrace > journal.CacheTraceVersion || seen && old != b.Core.CacheTrace || seen && s.run != b.Run && (old != 0 || b.Core.CacheTrace != 0) {
			return errCacheFrameSource
		}
		first = !seen
		s.versions[b.Run] = b.Core.CacheTrace
		if s.run != b.Run {
			s.peers = map[uint32]string{}
			s.indices = map[string]uint32{}
		}
		s.run = b.Run
	}
	version := s.versions[s.run]
	if version == 0 {
		switch b := rec.Body.(type) {
		case *journal.CacheRec:
			return errCacheFrameSource
		case *journal.MsgRec:
			if b.Attempt != nil {
				return errCacheFrameSource
			}
		case *journal.SuppressedRec:
			if b.Cache != 0 || b.Operation != 0 {
				return errCacheFrameSource
			}
		}
		return nil
	}
	if r.Offset == nil {
		return errCacheFrameSource
	}
	segment, err := strconv.ParseUint(strings.TrimSuffix(r.File, ".wal"), 10, 64)
	if err != nil {
		return errCacheFrameSource
	}
	r.Journal = &JournalPosition{number(segment), strconv.FormatInt(*r.Offset, 10)}
	code := ""
	switch b := rec.Body.(type) {
	case *journal.SegmentRec:
		if first {
			r.CacheTrace = &CacheTrace{Version: number(version), Complete: cacheBool(true)}
			r.ClockSource = "unavailable"
		}
	case *journal.PeerRec:
		peer := strings.ToLower(b.Addr.Hex())
		if old, ok := s.peers[b.PeerIdx]; ok && old != peer {
			return errCacheFrameSource
		}
		if old, ok := s.indices[peer]; ok && old != b.PeerIdx {
			return errCacheFrameSource
		}
		s.peers[b.PeerIdx], s.indices[peer] = peer, b.PeerIdx
	case *journal.CacheRec:
		if b.Action == "begin" {
			r.Type = "cache_instance"
			r.ClockSource = "unavailable"
			r.CacheInstance = &CacheInstance{Instance: number(b.Instance), Self: strings.ToLower(b.Self.Hex()), PeerCapacity: number(b.PeerCapacity), MessageCapacity: number(b.MessageCapacity), InitialState: "empty"}
		} else {
			r.Type = "cache_operation"
			r.ClockSource = "recorded"
			r.Mono = signed(int64(b.Mono))
			r.Wall = time.Unix(0, b.WallNs).UTC().Format(time.RFC3339Nano)
			r.CacheOperation = &CacheOperation{Instance: number(b.Instance), Sequence: number(b.Sequence), Action: b.Action, Peer: strings.ToLower(b.Peer.Hex()), Code: fmt.Sprintf("%#x", b.Code), Key: strings.ToLower(b.Key.Hex()), Payload: hex.EncodeToString(b.PayloadSHA256[:]), Cause: string(b.Cause), Known: cacheBool(b.Known), Recent: cacheBool(b.Recent), Available: cacheBool(b.Available), Candidates: cacheAddresses(b.Candidates), Targets: cacheAddresses(b.Targets), Suppressed: cacheAddresses(b.Suppressed)}
			r.Key, r.PayloadSHA256, r.Cause = r.CacheOperation.Key, r.CacheOperation.Payload, r.CacheOperation.Cause
			r.Phase = phase(b.Code)
			if !cacheZeroPeer(r.CacheOperation.Peer) {
				r.Peer = r.CacheOperation.Peer
				r.PeerStatus = "recorded"
			}
		}
	case *journal.MsgRec:
		code = fmt.Sprintf("%#x", b.Code)
		if b.Attempt != nil && codec.DedupKey(b.Payload) != b.DedupKey {
			return errCacheFrameSource
		}
		if b.Dir == journal.Out {
			r.SendAttempt = &SendAttempt{Available: cacheBool(b.Attempt != nil)}
			if a := b.Attempt; a != nil {
				r.SendAttempt.Sequence = number(a.Sequence)
				if a.Cache == 0 {
					r.SendAttempt.CacheAvailable = cacheBool(false)
				} else {
					r.SendAttempt.Decision = &CacheDecision{Instance: number(a.Cache), Operation: number(a.Operation), Available: cacheBool(false)}
				}
			}
		} else if b.Attempt != nil {
			return errCacheFrameSource
		}
	case *journal.SuppressedRec:
		if b.Cache != 0 {
			r.CacheDecision = &CacheDecision{Instance: number(b.Cache), Operation: number(b.Operation), Available: cacheBool(false)}
			r.ClockSource = "unavailable"
		}
	}
	raw := &cacheRawRecord{V: 1, Type: r.Type, Node: r.Node, Run: r.Run, ClockSource: r.ClockSource, Dir: r.Dir, Code: code, DedupKey: r.Key, Payload: r.PayloadSHA256, Cause: r.Cause, File: "journal", point: ownPoint(*r), JournalSegment: &segment, JournalOffset: r.Offset, CacheTrace: r.CacheTrace, CacheInstance: r.CacheInstance, CacheOperation: r.CacheOperation, CacheDecision: r.CacheDecision, SendAttempt: r.SendAttempt, present: map[string]bool{}}
	raw.Seq, err = strconv.ParseUint(r.Seq, 10, 64)
	if err != nil {
		return errCacheFrameSource
	}
	raw.TWall = time.Unix(0, 0).UTC().Format(time.RFC3339Nano)
	if r.Wall != "" {
		raw.TWall = r.Wall
	}
	if r.Mono != nil {
		raw.TMono, err = strconv.ParseInt(*r.Mono, 10, 64)
		if err != nil {
			return errCacheFrameSource
		}
	}
	if r.Peer != "" {
		p := r.Peer
		raw.Peer = &p
	}
	for _, k := range cacheCommonFields {
		raw.present[k] = true
	}
	raw.present["journal_segment"], raw.present["journal_offset"] = true, true
	if raw.CacheTrace != nil {
		raw.Type = "cache_trace"
		raw.present["cache_trace"], raw.present["clock_source"] = true, true
	}
	if raw.CacheInstance != nil {
		raw.present["cache_instance"], raw.present["clock_source"] = true, true
	}
	if raw.CacheOperation != nil {
		raw.present["cache_operation"] = true
	}
	if r.Type == "gap" {
		raw.Type = "dropped"
	}
	r.cacheRaw = raw
	return nil
}

// finishJournalCache closes the entire writer snapshot before any exact source
// link is emitted. Journal runs span segments, so their file grouping differs
// from R-01 while their returned source points retain the real WAL filename.
func finishJournalCache(rows []*cacheRawRecord) error {
	groups := map[string][]*cacheRawRecord{}
	for _, r := range rows {
		groups[r.Run] = append(groups[r.Run], r)
	}
	for _, rs := range groups {
		var trace *CacheTrace
		complete := true
		instances, operations := uint64(0), uint64(0)
		last := uint64(0)
		declared := map[string]bool{}
		seqs := map[string]uint64{}
		ops := map[[2]string]*cacheRawRecord{}
		for _, r := range rs {
			if r.Seq != last+1 {
				complete = false
			}
			last = r.Seq
			if r.CacheTrace != nil {
				if trace != nil {
					return errCacheFrameSource
				}
				trace = r.CacheTrace
			}
			if r.Type == "dropped" {
				complete = false
			}
			if i := r.CacheInstance; i != nil {
				instances++
				if seqs[i.Instance] != 0 {
					complete = false
				}
				declared[i.Instance] = true
			}
			if o := r.CacheOperation; o != nil {
				operations++
				n, ok := cacheUint(o.Sequence)
				if !ok || !declared[o.Instance] || n != seqs[o.Instance]+1 {
					complete = false
				}
				seqs[o.Instance] = n
				ops[[2]string{o.Instance, o.Sequence}] = r
			}
		}
		if trace == nil {
			return errCacheFrameSource
		}
		for _, r := range rs {
			ref := r.CacheDecision
			if r.SendAttempt != nil {
				ref = r.SendAttempt.Decision
			}
			if ref != nil && ops[[2]string{ref.Instance, ref.Operation}] == nil {
				complete = false
			}
		}
		trace.Instances, trace.Operations, trace.Complete = number(instances), number(operations), cacheBool(complete)
		for _, r := range rs {
			ref := r.CacheDecision
			if r.SendAttempt != nil {
				ref = r.SendAttempt.Decision
			}
			if ref == nil {
				continue
			}
			op := ops[[2]string{ref.Instance, ref.Operation}]
			if !complete || op == nil || r.Type == "frame" && r.Payload == "" {
				continue
			}
			ref.Available = cacheBool(true)
			ref.Seq, ref.Segment, ref.Offset = number(op.Seq), number(*op.JournalSegment), strconv.FormatInt(*op.JournalOffset, 10)
		}
	}
	return nil
}

func readJournal(ctx context.Context, p Prepared, chain, genesis string, emit func(Record) error) (Stats, error) {
	spool, err := os.CreateTemp("", "wbft-journal-cache-*")
	if err != nil {
		return Stats{}, errors.New("cannot create journal metadata spool")
	}
	defer func() { _ = spool.Close(); _ = os.Remove(spool.Name()) }()
	encoder := json.NewEncoder(spool)
	var rows []*cacheRawRecord
	sawSync := false
	stats, readErr := readJournalRaw(ctx, p, chain, genesis, func(r Record) error {
		sawSync = sawSync || r.syncJournal
		if r.cacheRaw != nil {
			rows = append(rows, r.cacheRaw)
		}
		if len(rows) > 1000000 {
			return errors.New("journal cache input exceeds one million records")
		}
		return encoder.Encode(r)
	})
	if domainprofile.Unsupported(readErr) || errors.Is(readErr, domainprofile.ErrInvalid) || errors.Is(readErr, ErrValidatorStartRestoreSource) || errors.Is(readErr, ErrReceiveFailureSource) || errors.Is(readErr, ErrRetrySource) || errors.Is(readErr, errRuntimeSource) || errors.Is(readErr, errCacheFrameSource) || errors.Is(readErr, errSyncSource) || errors.Is(readErr, errAppQueueSource) || errors.Is(readErr, errFinalizeSource) || errors.Is(readErr, errInboxSource) || errors.Is(readErr, errInternalSource) || errors.Is(readErr, errSelectionSource) || errors.Is(readErr, errReceiveDispatchSource) || errors.Is(readErr, errWALReadSource) || errors.Is(readErr, errRestoreSource) || errors.Is(readErr, errSignerSource) || errors.Is(readErr, errSignerCallSource) || errors.Is(readErr, errApplicationSource) {
		return Stats{}, readErr
	}
	if len(rows) > 0 {
		if readErr != nil {
			return stats, readErr
		}
		if err = finishJournalCache(rows); err != nil {
			return Stats{}, err
		}
		sum, e := Fingerprint(ctx, p.Input)
		if e != nil || p.Summary.SHA256 == "" || sum.SHA256 != p.Summary.SHA256 {
			return Stats{}, errors.New("journal cache source changed during read")
		}
	}
	var syncRows []syncSourceRow
	if sawSync {
		if readErr != nil {
			return stats, readErr
		}
		if len(rows) == 0 {
			sum, e := Fingerprint(ctx, p.Input)
			if e != nil || p.Summary.SHA256 == "" || sum.SHA256 != p.Summary.SHA256 {
				return Stats{}, errors.New("journal sync source changed during read")
			}
		}
		syncRows, err = readSyncSpool(ctx, spool)
		if err != nil {
			return Stats{}, err
		}
	}
	syncProofs, err := finishSyncSources(syncRows, true, false)
	if err != nil {
		return Stats{}, err
	}
	proofs, err := cacheFrameProofs(rows)
	if err != nil {
		return Stats{}, err
	}
	bySource := map[ownRecordKey]*cacheRawRecord{}
	for _, r := range rows {
		bySource[ownRecordKey{ownScope{r.point.Input, r.point.File, r.Node, r.Run}, number(r.Seq)}] = r
	}
	if _, err = spool.Seek(0, io.SeekStart); err != nil {
		return Stats{}, errors.New("cannot rewind journal metadata")
	}
	decoder := json.NewDecoder(spool)
	for {
		if err = ctx.Err(); err != nil {
			return stats, err
		}
		var r Record
		err = decoder.Decode(&r)
		if err == io.EOF {
			break
		}
		if err != nil {
			return Stats{}, errors.New("cannot read journal metadata spool")
		}
		k := ownKey(r)
		if raw := bySource[k]; raw != nil {
			r.CacheTrace, r.SendAttempt, r.CacheDecision = raw.CacheTrace, raw.SendAttempt, raw.CacheDecision
		}
		r.CacheEvidence = proofs[k]
		if source, ok := syncProofs[k]; ok {
			r.SyncTrace, r.SyncControl, r.SyncEvidence = source.SyncTrace, source.SyncControl, source.SyncEvidence
		}
		if err = emit(r); err != nil {
			return stats, err
		}
	}
	return stats, readErr
}
