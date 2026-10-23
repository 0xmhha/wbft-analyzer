package messages

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"encoding/binary"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
	"os"
)

func Read(ctx context.Context, p Prepared, networkChain, networkGenesis string, emit func(Record) error) (Stats, error) {
	switch p.Input.Kind {
	case "frames":
		return readFrames(ctx, p, emit)
	case "journal":
		return readJournal(ctx, p, networkChain, networkGenesis, emit)
	case "sync_notifications":
		return readSyncNotifications(ctx, p, emit)
	default:
		return Stats{}, errors.New("invalid message input kind")
	}
}

func readJournalRaw(ctx context.Context, p Prepared, chain, genesis string, emit func(Record) error) (s Stats, err error) {
	s.ClockDiagnostics = "recorded_sequence"
	root, e := os.OpenRoot(p.Input.Path)
	if e != nil {
		return s, errors.New("cannot open journal input")
	}
	defer root.Close()
	ends := map[string]int64{}
	rd, e := journal.OpenReader(nil, p.Input.Path)
	if e != nil {
		return s, errors.New("cannot open journal reader")
	}
	run := ""
	last := uint64(0)
	peers := map[uint32]string{}
	previousMono := int64(0)
	haveMono := false
	var nextHeight *journal.DeferredOptions
	cacheState := newJournalCacheState()
	syncState := newJournalSyncState()
	for {
		if e = ctx.Err(); e != nil {
			return s, e
		}
		rec, pos, e := rd.NextAt()
		if e == io.EOF {
			return s, journalTail(p, ends)
		}
		if e != nil {
			return s, errors.New("journal damaged or incomplete; readable prefix retained")
		}
		name := fmt.Sprintf("%020d.wal", pos.Segment)
		f, e := root.Open(name)
		if e != nil {
			return s, errors.New("cannot verify journal boundary")
		}
		var length [4]byte
		_, e = f.ReadAt(length[:], pos.Offset)
		f.Close()
		if e != nil {
			return s, errors.New("cannot read journal boundary")
		}
		ends[name] = pos.Offset + 8 + int64(binary.BigEndian.Uint32(length[:]))
		r := Record{Input: p.Input.ID, File: fmt.Sprintf("%020d.wal", pos.Segment), Ordinal: s.Records + 1, Offset: &pos.Offset, Seq: number(rec.JSeq), Node: p.Summary.Node, Run: run}
		if b, ok := rec.Body.(*journal.SegmentRec); ok {
			if addr(b.Self) != p.Summary.Node || b.ChainID == nil || b.ChainID.String() != chain || !strings.EqualFold(b.GenesisHash.Hex(), genesis) || b.Run == "" || len(b.Run) > 128 {
				return s, errors.New("journal segment identity mismatch")
			}
			if b.Run != run {
				run = b.Run
				last = 0
				peers = map[uint32]string{}
				haveMono = false
			}
			r.Run = run
			r.Type = "segment"
			r.EngineRun = number(b.EngineRun)
			r.ConfigDigest = hash(b.ConfigDigest)
			r.Improvements = number(b.Core.Improvements)
			if err := b.Core.NextHeight.Validate(); err != nil {
				return s, errors.New("unsupported next-height receive profile")
			}
			nextHeight = b.Core.NextHeight
			r.NextHeight = ProjectReceiveProfile(nextHeight)
			if b.Core.TimerTrace != 0 {
				r.TimerTrace = number(b.Core.TimerTrace)
			}
		} else if run == "" {
			return s, errors.New("journal missing segment identity")
		}
		if rec.JSeq == 0 || rec.JSeq <= last {
			return s, errors.New("journal sequence duplicate or regression")
		}
		if last == 0 && rec.JSeq != 1 {
			s.PartialRuns++
		}
		if last != 0 && rec.JSeq-last > 1 {
			s.SequenceGaps++
		}
		last = rec.JSeq
		switch b := rec.Body.(type) {
		case *journal.SegmentRec:
		case *journal.PeerRec:
			r.Type = "conn"
			r.Peer = addr(b.Addr)
			r.Event = choice(b.Event, "attached", "closed")
			switch b.Event {
			case "attached":
				peers[b.PeerIdx] = r.Peer
			case "closed":
				if r.Peer != "" {
					peers[b.PeerIdx] = r.Peer
				}
			}
		case *journal.MsgRec:
			if b.Session != nil || b.WriteAttempt != nil {
				return s, errCacheFrameSource
			}
			r.IO = journalIOInterval(b.IO)
			r.Type = "frame"
			if b.Capture != 0 {
				r.Capture = number(b.Capture)
			}
			r.ClockSource = "recorded"
			r.Dir = choice(b.Dir, "in", "out")
			r.Peer = peers[b.PeerIdx]
			if r.Peer == "" {
				r.PeerStatus = "unknown"
			} else {
				r.PeerStatus = "recorded"
			}
			r.Mono = signed(int64(b.Mono))
			r.Wall = time.Unix(0, b.WallNs).UTC().Format(time.RFC3339Nano)
			v := number(b.WireCode)
			r.WireCode = &v
			size := b.Size
			if size == 0 {
				size = uint64(len(b.Payload))
			}
			v = number(size)
			r.Size = &v
			r.Key = hash(b.DedupKey)
			r.Engine = choice(b.Engine, "running", "stopped", "syncing")
			r.Offer = choice(b.Offer, "queued", "queue_full", "frame_ignore", "frame_disconnect")
			r.Write = choice(b.Write, "ok", "error", "not_attached")
			r.Cause = choice(string(b.Cause), "broadcast", "gossip", "relay", "retry", "reconnect", "replay", "direct")
			if b.RelayOf != 0 {
				r.RelayOf = number(b.RelayOf)
			}
			if b.Dedup != nil {
				r.KnownHit = &b.Dedup.Known
				r.PeerRecentHit = &b.Dedup.PeerRecent
			}
			decode(&r, b.Code, b.Payload, size > uint64(len(b.Payload)))
		case *journal.OutcomeRec:
			r.Type = "outcome"
			if b.EngineRun != 0 {
				r.EngineRun = number(b.EngineRun)
			}
			r.Peer = addr(b.Peer)
			r.Key = hash(b.DedupKey)
			r.Phase = phase(b.Code)
			r.Outcome = choice(string(b.Outcome), "ACCEPT", "IGNORE", "DROP_SILENT", "DISCONNECT")
			r.Check = choice(b.Check, "PROCESS", "FUTURE", "OLD", "INVALID", "EXTRA_SEAL", "TOO_FAR", "prefilter")
			r.Via = choice(b.Via, "direct", "backlog", "future_block", "self")
			if b.Of != 0 {
				r.Of = number(b.Of)
			}
			if b.Step != 0 {
				r.Step = number(b.Step)
			}
			if b.AtOffer {
				r.Offer = "at_offer"
			}
		case *journal.SuppressedRec:
			r.Type = "send_suppressed"
			r.Peer = peers[b.PeerIdx]
			r.Key = hash(b.DedupKey)
			r.Cause = choice(string(b.Cause), "broadcast", "gossip", "relay", "retry", "reconnect", "replay", "direct")
		case *journal.StepRec:
			r.Type = "step"
			if b.InputKind == inputlog.KindCapturedMessage {
				if id, e := inputlog.CapturedReference(b.Input); e == nil {
					r.Capture = number(id)
				}
			}
			if b.InputKind == inputlog.KindDeferredMessage {
				if nextHeight == nil {
					return s, errors.New("deferred input has no receive profile")
				}
				_, evidence, err := journal.InspectDeferred(rd, b.Input)
				if err != nil {
					return s, errors.New("deferred input cannot be decoded")
				}
				r.DeferredOrigin = ProjectDeferredEvidence(evidence)
				r.InputKind = inputlog.KindDeferredMessage
			}
			r.ClockSource = "recorded"
			r.EngineRun = number(b.EngineRun)
			r.Step = number(b.Step)
			r.Mono = signed(int64(b.Mono))
			r.Wall = time.Unix(0, b.WallNs).UTC().Format(time.RFC3339Nano)
			if b.Entry != nil {
				r.EntryMono = signed(int64(b.Entry.Mono))
				r.EntryWall = time.Unix(0, b.Entry.WallNs).UTC().Format(time.RFC3339Nano)
			}
			r.HeadNumber = b.HeadNumber.String()
			r.HeadHash = hash(b.HeadHash)
			r.OutDigest = hash(b.OutDigest)
			r.Via = choice(b.Via, "internal", "app", "timer", "peer", "wal")
		case *journal.AppQueueRec:
			return s, errAppQueueSource
		case *journal.WriteCacheRec, *journal.ReceiveCacheRec, *journal.SessionRec, *journal.CoreStepRec:
			return s, errCacheFrameSource
		case *journal.CacheRec:
			// The closed cache projection below also checks its run capability.
		case *journal.SyncRec:
			// The sync projection below retains the actual control-call cursors.
		case *journal.TimerRec:
			r.Type = "timer_operation"
			r.ClockSource = "recorded"
			r.EngineRun = number(b.EngineRun)
			r.Step = number(b.Step)
			r.Mono = signed(int64(b.Mono))
			r.Wall = time.Unix(0, b.WallNs).UTC().Format(time.RFC3339Nano)
			r.Timer = projectTimerOperation(b)
			r.Height, r.Round = r.Timer.Height, r.Timer.Round
		case *journal.GapRec:
			r.Type = "gap"
			r.Dropped = number(b.Dropped)
			r.GapFirstMono = strconv.FormatInt(int64(b.FirstMono), 10)
			r.GapLastMono = strconv.FormatInt(int64(b.LastMono), 10)
		default:
			return s, errors.New("unsupported journal record")
		}
		if err := syncState.project(&r, rec); err != nil {
			return s, err
		}
		if err := cacheState.project(&r, rec); err != nil {
			return s, err
		}
		if r.Mono != nil {
			n, _ := strconv.ParseInt(*r.Mono, 10, 64)
			if haveMono && n < previousMono {
				s.ClockRegressions++
			}
			previousMono = n
			haveMono = true
		}
		if e = emit(r); e != nil {
			return s, e
		}
		observe(&s, r)
	}
}

// The public journal reader intentionally treats a torn final frame as EOF.
// Compare the public WAL envelope's end positions with fingerprinted
// file lengths so ingestion never declares such a prefix complete.
func journalTail(p Prepared, ends map[string]int64) error {
	for _, f := range p.Summary.Files {
		if strings.HasSuffix(f.Name, ".wal") && ends[f.Name] != f.Bytes {
			return errors.New("journal incomplete tail; readable prefix retained")
		}
	}
	return nil
}
