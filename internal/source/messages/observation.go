package messages

import "github.com/0xmhha/wbft/observe/journal"

// ObservationProfile projects a validated declaration, not authenticated state.
// Exact decimal fields retain their precision through API and browser clients.
type ObservationProfile struct {
	Version          string            `json:"version"`
	PolicyDigest     string            `json:"policy_digest"`
	Activation       string            `json:"activation"`
	Retention        string            `json:"retention"`
	Window           string            `json:"window"`
	HistoryWalk      string            `json:"history_walk"`
	ReplayHeaders    string            `json:"replay_headers"`
	CheckpointStatus string            `json:"checkpoint_status"`
	Limits           map[string]string `json:"limits"`
}

func projectObservationProfile(segment *journal.SegmentRec) (*ObservationProfile, error) {
	o := segment.Core.Observation
	if o == nil {
		return nil, nil
	}
	if err := o.ValidateIdentity(segment.ChainID, segment.GenesisHash); err != nil {
		return nil, err
	}
	checkpoint := "absent"
	if len(o.Checkpoint) != 0 {
		checkpoint = "recorded_requires_chain"
	}
	return &ObservationProfile{Version: number(o.Profile), PolicyDigest: hash(o.PolicyDigest), Activation: o.Activation,
		Retention: o.Retention, Window: number(o.Window), HistoryWalk: number(o.HistoryWalk), ReplayHeaders: number(o.ReplayHeaders),
		CheckpointStatus: checkpoint, Limits: map[string]string{
			"extra_bytes": number(o.Codec.ExtraBytes), "proofs": number(uint64(o.Codec.Proofs)),
			"settlement_rows": number(uint64(o.Codec.SettlementRows)), "validators": number(uint64(o.Codec.Validators)),
			"state_bytes": number(o.StateBytes), "checkpoint_bytes": number(o.CheckpointBytes), "address_rows": number(uint64(o.AddressRows)),
		}}, nil
}
