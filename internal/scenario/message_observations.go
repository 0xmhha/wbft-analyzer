package scenario

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/consensus/inputlog"
	"github.com/0xmhha/wbft/observe/journal"
)

type SeedMessageObservations struct {
	Source  string              `json:"source"`
	Changes []SeedMessageChange `json:"changes"`
}
type SeedMessageChange struct {
	Kind          string               `json:"kind"`
	Status        string               `json:"status"`
	FirstMatches  uint64               `json:"first_matches,string"`
	SecondMatches uint64               `json:"second_matches,string"`
	First         *SeedMessageDelivery `json:"first,omitempty"`
	Second        *SeedMessageDelivery `json:"second,omitempty"`
}
type SeedMessageDelivery struct {
	SentNS        int64                  `json:"sent_ns,string"`
	EligibleNS    int64                  `json:"eligible_ns,string"`
	ReleasedNS    *int64                 `json:"released_ns,string,omitempty" nullable:"false"`
	PeerRun       string                 `json:"peer_run"`
	ReceiverRun   string                 `json:"receiver_run"`
	PayloadSHA256 string                 `json:"simulated_payload_sha256"`
	Arrival       uint64                 `json:"arrival_order,string"`
	Release       uint64                 `json:"release_order,string"`
	Capture       uint64                 `json:"capture_id,string"`
	Offer         string                 `json:"offer"`
	CoreInputs    []SeedMessageCoreInput `json:"recorded_core_inputs"`
}
type SeedMessageCoreInput struct {
	Engine          uint64 `json:"engine_run,string"`
	Step            uint64 `json:"step,string"`
	JournalSequence uint64 `json:"journal_sequence,string"`
	MonoNS          int64  `json:"recorded_step_mono_ns,string"`
	EntryNS         *int64 `json:"entry_ns,string,omitempty" nullable:"false"`
}

func simulateMessageSeed(ctx context.Context, sc sim.Scenario) (*sim.Result, *SeedMessageObservations, error) {
	dir, err := os.MkdirTemp("", "wbft-analyzer-selected-messages-")
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	result, runErr := sim.Run(ctx, sc, sim.Output{JournalDir: dir})
	if runErr != nil && !errors.Is(runErr, sim.ErrMessageSelection) {
		return nil, nil, runErr
	}
	if result == nil {
		return nil, nil, errors.New("simulator message result missing")
	}
	observed, err := observedMessages(ctx, sc, result, dir)
	if err != nil {
		return result, nil, err
	}
	return result, observed, runErr
}

func observedMessages(ctx context.Context, sc sim.Scenario, result *sim.Result, dir string) (*SeedMessageObservations, error) {
	if len(sc.MessageChanges) != len(result.MessageDeliveries) {
		return nil, errors.New("simulator message observations incomplete")
	}
	out := &SeedMessageObservations{Source: "simulator_transport_and_captured_message_journal/1", Changes: []SeedMessageChange{}}
	type target struct {
		packet *SeedMessageDelivery
		hash   string
		seen   int
	}
	wanted := map[int]map[string]*target{}
	for i, row := range result.MessageDeliveries {
		expected := sc.MessageChanges[i]
		if expected.Kind != row.Change.Kind || expected.First != row.Change.First || (expected.Second == nil) != (row.Change.Second == nil) || expected.Second != nil && *expected.Second != *row.Change.Second {
			return nil, errors.New("simulator message selection differs")
		}
		change := SeedMessageChange{Kind: row.Change.Kind, Status: row.Status, FirstMatches: row.FirstMatches, SecondMatches: row.SecondMatches}
		copyPacket := func(packet *sim.SelectedMessageDelivery, selector sim.MessageSelector) (*SeedMessageDelivery, error) {
			if packet == nil {
				return nil, nil
			}
			p := &SeedMessageDelivery{SentNS: int64(packet.SentAt), EligibleNS: int64(packet.EligibleAt), PeerRun: packet.PeerRun, ReceiverRun: packet.ReceiverRun, PayloadSHA256: hex.EncodeToString(packet.PayloadSHA256[:]), Arrival: packet.ArrivalOrder, Release: packet.ReleaseOrder, Capture: packet.Capture, Offer: packet.Offer, CoreInputs: []SeedMessageCoreInput{}}
			if packet.ReleasedAt != nil {
				n := int64(*packet.ReleasedAt)
				p.ReleasedNS = &n
			}
			if packet.Capture == 0 {
				return p, nil
			}
			if p.ReleasedNS == nil {
				return nil, errors.New("selected capture lacks delivery time")
			}
			for node, v := range sc.Validators {
				if v.Address() != selector.Receiver {
					continue
				}
				if wanted[node] == nil {
					wanted[node] = map[string]*target{}
				}
				key := fmt.Sprintf("%s/%d", packet.ReceiverRun, packet.Capture)
				if wanted[node][key] != nil {
					return nil, errors.New("duplicate selected capture")
				}
				wanted[node][key] = &target{packet: p, hash: p.PayloadSHA256}
				return p, nil
			}
			return nil, errors.New("selected receiver unavailable")
		}
		var err error
		change.First, err = copyPacket(row.First, row.Change.First)
		if err != nil {
			return nil, err
		}
		if row.Change.Second != nil {
			change.Second, err = copyPacket(row.Second, *row.Change.Second)
			if err != nil {
				return nil, err
			}
		}
		out.Changes = append(out.Changes, change)
	}
	// Read in node order. Writer run plus capture binds packets across restarts;
	// no missing core input is labelled as dedup, rejection, or handler entry.
	for node, v := range sc.Validators {
		if len(wanted[node]) == 0 {
			continue
		}
		reader, err := journal.OpenReader(nil, filepath.Join(dir, strings.TrimPrefix(strings.ToLower(v.Address().Hex()), "0x")))
		if err != nil {
			return nil, err
		}
		run := ""
		for {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			record, err := reader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			switch body := record.Body.(type) {
			case *journal.SegmentRec:
				if body.Self != v.Address() || body.Run == "" {
					return nil, errors.New("message journal identity mismatch")
				}
				run = body.Run
			case *journal.MsgRec:
				if body.Dir != journal.In || body.Capture == 0 {
					continue
				}
				if target := wanted[node][fmt.Sprintf("%s/%d", run, body.Capture)]; target != nil {
					hash := sha256.Sum256(body.Payload)
					if hex.EncodeToString(hash[:]) != target.hash || int64(body.Mono) != *target.packet.ReleasedNS || body.Offer != target.packet.Offer {
						return nil, errors.New("selected capture disagrees with delivery")
					}
					target.seen++
				}
			case *journal.StepRec:
				if body.InputKind != inputlog.KindCapturedMessage {
					continue
				}
				capture, err := inputlog.CapturedReference(body.Input)
				if err != nil {
					return nil, err
				}
				if target := wanted[node][fmt.Sprintf("%s/%d", run, capture)]; target != nil {
					step := SeedMessageCoreInput{Engine: body.EngineRun, Step: body.Step, JournalSequence: record.JSeq, MonoNS: int64(body.Mono)}
					if body.Entry != nil {
						ns := int64(body.Entry.Mono)
						step.EntryNS = &ns
					}
					target.packet.CoreInputs = append(target.packet.CoreInputs, step)
				}
			}
		}
		for _, target := range wanted[node] {
			if target.seen != 1 {
				return nil, errors.New("selected capture missing or ambiguous")
			}
		}
	}
	return out, nil
}
