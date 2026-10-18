package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/privacy"
	"github.com/0xmhha/wbft-analyzer/internal/source/governance"
	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/0xmhha/wbft/types"
	"github.com/jackc/pgx/v5"
)

// Header context is evaluated when read. Appending headers never mutates the
// immutable governance capture, source entries or their pagination snapshot.
type GovernanceHeaderContext struct {
	Snapshot         string                   `json:"snapshot"`
	CallOrdinal      int                      `json:"call_ordinal"`
	EntryOrdinal     int                      `json:"entry_ordinal"`
	Collection       string                   `json:"collection" enum:"operations,changes"`
	Pointer          string                   `json:"normalized_pointer"`
	SourceNumber     string                   `json:"source_number"`
	Index            string                   `json:"index"`
	SourceBlockHash  *string                  `json:"source_block_hash"`
	HeaderStatus     string                   `json:"header_status" enum:"unknown_hash,header_unavailable,hash_mismatch,matched"`
	CanonicalHash    *string                  `json:"canonical_hash"`
	Header           *GovernanceHeader        `json:"header"`
	Sources          []GovernanceHeaderSource `json:"sources"`
	SourcesTruncated bool                     `json:"sources_truncated"`
	Epoch            *GovernanceEpochEvidence `json:"epoch"`
	CauseStatus      string                   `json:"cause_status" enum:"unestablished"`
}

type GovernanceHeader struct {
	Index  string `json:"index"`
	Number string `json:"number"`
	Hash   string `json:"hash"`
	Epoch  string `json:"governing_epoch"`
}

type GovernanceHeaderSource struct {
	DatasetID int64  `json:"dataset_id"`
	Node      string `json:"node"`
	Status    string `json:"dataset_status"`
}

// Ordered epoch claims are compared separately. NoKey requires execution state
// and is never verified by a matching header or its reconstructed BLS inputs.
type GovernanceEpochEvidence struct {
	Status           string                       `json:"status" enum:"available,not_epoch,header_epoch_unavailable"`
	Candidates       string                       `json:"candidates" enum:"matched,mismatch,unavailable"`
	Validators       string                       `json:"validators" enum:"matched,mismatch,unavailable"`
	Added            string                       `json:"added" enum:"matched,mismatch,unavailable"`
	Removed          string                       `json:"removed" enum:"matched,mismatch,unavailable"`
	HeaderCandidates []string                     `json:"header_candidates"`
	HeaderValidators []string                     `json:"header_validators"`
	HeaderAdded      []string                     `json:"header_added"`
	HeaderRemoved    []string                     `json:"header_removed"`
	NoKeyStatus      string                       `json:"no_key_status" enum:"unverified_execution_keys,verified_execution_keys,mismatch_execution_keys,ambiguous_execution_keys"`
	ExecutionState   *GovernanceStateEvidenceList `json:"execution_state"`
}

func (s *Store) GovernanceHeaderContext(ctx context.Context, id int64, call, entry int, collection string) (result GovernanceHeaderContext, err error) {
	result = GovernanceHeaderContext{CallOrdinal: call, EntryOrdinal: entry, Collection: collection, Sources: []GovernanceHeaderSource{}, CauseStatus: "unestablished"}
	if call < 1 || entry < 1 || collection != "operations" && collection != "changes" {
		return result, ErrGovernanceQuery
	}
	err = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var raw []byte
		var network int64
		if err := tx.QueryRow(ctx, `SELECT c.info,d.network_id FROM governance_captures c JOIN datasets d ON d.id=c.dataset_id JOIN networks n ON n.id=d.network_id WHERE d.id=$1 AND d.kind='governance' AND d.status='complete' AND d.visibility=$2 AND n.visibility=$2`, id, privacy.Visibility()).Scan(&raw, &network); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		var capture GovernanceCapture
		if err := json.Unmarshal(raw, &capture); err != nil {
			return err
		}
		if call > len(capture.Calls) || capture.Calls[call-1].Ordinal != call || !GovernanceCollection(capture.Calls[call-1].Request.Method, collection) {
			return ErrGovernanceQuery
		}
		result.Snapshot = capture.Snapshot
		// Identifiers come exclusively from the two fixed collection names.
		table, path := "gov_ops", "source_path"
		if collection == "changes" {
			table, path = "gov_validator_changes", "(ordinal-1)::text"
		}
		var pointer string
		if err := tx.QueryRow(ctx, `SELECT number::text,`+path+`,row_ FROM `+table+` WHERE dataset_id=$1 AND call_ordinal=$2 AND ordinal=$3`, id, call, entry).Scan(&result.Index, &pointer, &raw); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		result.Pointer = "/data/" + pointer
		var epochClaim *governance.Epoch
		if collection == "operations" {
			var op governance.Operation
			if err := json.Unmarshal(raw, &op); err != nil {
				return err
			}
			result.SourceNumber, result.SourceBlockHash = op.Number, op.BlockHash
		} else {
			var change GovernanceChange
			if err := json.Unmarshal(raw, &change); err != nil {
				return err
			}
			result.SourceNumber, result.SourceBlockHash, epochClaim = change.Number, change.BlockHash, change.Epoch
		}
		if result.SourceBlockHash == nil {
			result.HeaderStatus = "unknown_hash"
			return nil
		}
		var hash string
		if err := tx.QueryRow(ctx, `SELECT hash,fact FROM heights WHERE network_id=$1 AND index_=$2::numeric`, network, result.Index).Scan(&hash, &raw); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				result.HeaderStatus = "header_unavailable"
				return nil
			}
			return err
		}
		result.CanonicalHash = &hash
		if !strings.EqualFold(hash, *result.SourceBlockHash) {
			result.HeaderStatus = "hash_mismatch"
			return nil
		}
		var fact headers.Fact
		if err := json.Unmarshal(raw, &fact); err != nil {
			return err
		}
		if fact.Index != result.Index || fact.Hash != hash {
			return errors.New("inconsistent canonical header fact")
		}
		result.HeaderStatus = "matched"
		result.Header = &GovernanceHeader{Index: fact.Index, Number: fact.Number, Hash: fact.Hash, Epoch: fact.Epoch}
		if epochClaim != nil {
			result.Epoch = compareGovernanceEpoch(fact, *epochClaim)
		}
		rows, err := tx.Query(ctx, `SELECT hc.dataset_id,hc.node,d.status FROM header_copies hc JOIN datasets d ON d.id=hc.dataset_id WHERE d.network_id=$1 AND d.visibility=$4 AND hc.index_=$2::numeric AND hc.hash=$3 ORDER BY hc.dataset_id,hc.node LIMIT 21`, network, result.Index, hash, privacy.Visibility())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var source GovernanceHeaderSource
			if err := rows.Scan(&source.DatasetID, &source.Node, &source.Status); err != nil {
				return err
			}
			result.Sources = append(result.Sources, source)
		}
		if len(result.Sources) > 20 {
			result.Sources, result.SourcesTruncated = result.Sources[:20], true
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if result.Epoch != nil {
			evidence, err := governanceStateEvidence(ctx, tx, network, id, result.Index)
			if err != nil {
				return err
			}
			applyGovernanceState(result.Epoch, *epochClaim, evidence)
		}
		return nil
	})
	return result, err
}

func compareGovernanceEpoch(fact headers.Fact, claim governance.Epoch) *GovernanceEpochEvidence {
	result := &GovernanceEpochEvidence{Status: "header_epoch_unavailable", Candidates: "unavailable", Validators: "unavailable", Added: "unavailable", Removed: "unavailable", HeaderCandidates: []string{}, HeaderValidators: []string{}, HeaderAdded: []string{}, HeaderRemoved: []string{}, NoKeyStatus: "unverified_execution_keys"}
	if string(fact.EpochInfo) == "null" {
		result.Status = "not_epoch"
		return result
	}
	var info types.EpochInfo
	if len(fact.EpochInfo) == 0 || json.Unmarshal(fact.EpochInfo, &info) != nil || len(info.Candidates) == 0 || len(info.Validators) == 0 {
		return result
	}
	for _, index := range info.Validators {
		if uint64(index) >= uint64(len(info.Candidates)) {
			return result
		}
	}
	for _, candidate := range info.Candidates {
		result.HeaderCandidates = append(result.HeaderCandidates, candidate.Addr.Hex())
	}
	for _, index := range info.Validators {
		result.HeaderValidators = append(result.HeaderValidators, info.Candidates[index].Addr.Hex())
	}
	result.Status = "available"
	compare := func(a, b []string) string {
		if len(a) != len(b) {
			return "mismatch"
		}
		for i := range a {
			if !strings.EqualFold(a[i], b[i]) {
				return "mismatch"
			}
		}
		return "matched"
	}
	result.Candidates, result.Validators = compare(claim.Candidates, result.HeaderCandidates), compare(claim.Validators, result.HeaderValidators)
	// At genesis Fact.Validators comes from configuration, not a preceding epoch.
	// Missing governing inputs also leave deltas unknown; no nearest-epoch guess.
	if fact.Index == "0" || len(fact.Validators) == 0 {
		return result
	}
	previous, next := map[string]bool{}, map[string]bool{}
	for _, address := range fact.Validators {
		previous[strings.ToLower(address)] = true
	}
	for _, address := range result.HeaderValidators {
		next[strings.ToLower(address)] = true
	}
	for _, address := range result.HeaderValidators {
		if !previous[strings.ToLower(address)] {
			result.HeaderAdded = append(result.HeaderAdded, address)
		}
	}
	for _, address := range fact.Validators {
		if !next[strings.ToLower(address)] {
			result.HeaderRemoved = append(result.HeaderRemoved, address)
		}
	}
	result.Added, result.Removed = compare(claim.Added, result.HeaderAdded), compare(claim.Removed, result.HeaderRemoved)
	return result
}
