package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/0xmhha/wbft-analyzer/internal/privacy"
	"github.com/0xmhha/wbft-analyzer/internal/source/governance"
	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/0xmhha/wbft-analyzer/internal/source/statewitness"
	"github.com/0xmhha/wbft/types"
	"github.com/jackc/pgx/v5"
)

var ErrStateWitnessBinding = errors.New("execution-state witness has no matching completed governance and header sources")

type GovernanceStateWitness struct {
	DatasetID      int64                 `json:"dataset_id"`
	Snapshot       string                `json:"snapshot"`
	HeadersDataset *int64                `json:"headers_dataset"`
	HeaderSourceID int64                 `json:"header_source_id"`
	Source         statewitness.Snapshot `json:"source"`
	Points         int                   `json:"points"`
}

// GovernanceStateEvidence re-evaluates source binding when read. Persisted
// cryptographic evidence never substitutes for a missing canonical dataset.
type GovernanceStateEvidence struct {
	Witness GovernanceStateWitness `json:"witness"`
	Point   statewitness.Point     `json:"point"`
	Status  string                 `json:"status" enum:"matched,header_unavailable,header_mismatch,config_mismatch,network_mismatch,source_unavailable"`
}

type GovernanceStateEvidenceList struct {
	Index     string                    `json:"index"`
	Evidence  []GovernanceStateEvidence `json:"evidence"`
	Truncated bool                      `json:"truncated"`
}

// PutGovernanceStateWitness accepts an opaque bundle produced by the source
// loader, never a deserialized report claiming that proofs were verified.
func (s *Store) PutGovernanceStateWitness(ctx context.Context, dataset, headerDataset int64, bundle statewitness.Bundle) (GovernanceStateWitness, error) {
	var result GovernanceStateWitness
	source := bundle.Projection()
	if dataset < 1 || headerDataset < 1 || dataset == headerDataset || source.Format != statewitness.InputFormat || len(source.Points) == 0 || len(source.Points) > statewitness.MaxWitnessPoints {
		return result, ErrStateWitnessBinding
	}
	ids := []int64{dataset, headerDataset}
	slices.Sort(ids)
	for _, id := range ids {
		release, err := s.DatasetReadLease(ctx, id)
		if err != nil {
			return result, err
		}
		defer release()
	}
	raw, err := json.Marshal(struct {
		Header int64                 `json:"headers_dataset"`
		Source statewitness.Snapshot `json:"source"`
	}{headerDataset, source})
	if err != nil {
		return result, err
	}
	sum := sha256.Sum256(raw)
	result = GovernanceStateWitness{DatasetID: dataset, Snapshot: hex.EncodeToString(sum[:]), HeadersDataset: &headerDataset, HeaderSourceID: headerDataset, Source: source, Points: len(source.Points)}
	// The parent keeps bounded source metadata; indexed child rows own each
	// point. Neither table contains the original proof payload or local paths.
	result.Source.Points = []statewitness.Point{}
	info, err := json.Marshal(result.Source)
	if err != nil {
		return result, err
	}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var network int64
		var chain, genesis, status, visibility, node string
		var captureRaw []byte
		err := tx.QueryRow(ctx, `SELECT d.network_id,n.chain_id,n.genesis_hash,d.status,d.visibility,c.node,c.info FROM datasets d JOIN networks n ON n.id=d.network_id JOIN governance_captures c ON c.dataset_id=d.id WHERE d.id=$1 AND d.kind='governance' AND n.visibility=$2 FOR UPDATE OF d`, dataset, privacy.Visibility()).Scan(&network, &chain, &genesis, &status, &visibility, &node, &captureRaw)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrStateWitnessBinding
		}
		if err != nil {
			return err
		}
		if status != "complete" || visibility != privacy.Visibility() || chain != source.ChainID || !strings.EqualFold(genesis, source.GenesisHash) || !strings.EqualFold(node, source.Node) {
			return ErrStateWitnessBinding
		}
		var capture GovernanceCapture
		if json.Unmarshal(captureRaw, &capture) != nil || capture.DatasetID != dataset || !sameWitnessIdentity(capture, source) {
			return ErrStateWitnessBinding
		}
		for _, point := range source.Points {
			if !witnessIndexInRange(point.Index, capture.From, capture.To) {
				return ErrStateWitnessBinding
			}
			binding, err := bindWitnessHeader(ctx, tx, network, headerDataset, source, point)
			if err != nil {
				return err
			}
			if binding != "matched" {
				return ErrStateWitnessBinding
			}
		}
		tag, err := tx.Exec(ctx, `INSERT INTO governance_state_witnesses(dataset_id,snapshot,header_dataset_id,header_source_id,info) VALUES($1,$2,$3,$3,$4) ON CONFLICT(dataset_id,snapshot) DO UPDATE SET snapshot=governance_state_witnesses.snapshot WHERE governance_state_witnesses.info=EXCLUDED.info AND governance_state_witnesses.header_dataset_id=EXCLUDED.header_dataset_id AND governance_state_witnesses.header_source_id=EXCLUDED.header_source_id`, dataset, result.Snapshot, headerDataset, info)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrStateWitnessBinding
		}
		for _, point := range source.Points {
			raw, err := json.Marshal(point)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO governance_state_points(dataset_id,snapshot,index_,point) VALUES($1,$2,$3::numeric,$4) ON CONFLICT DO NOTHING`, dataset, result.Snapshot, point.Index, raw); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return GovernanceStateWitness{}, err
	}
	return result, nil
}

func sameWitnessIdentity(capture GovernanceCapture, source statewitness.Snapshot) bool {
	for _, identity := range []struct{ node, chain, genesis string }{
		{capture.Before.Address, capture.Before.ChainID, capture.Before.GenesisHash},
		{capture.After.Address, capture.After.ChainID, capture.After.GenesisHash},
	} {
		if !strings.EqualFold(identity.node, source.Node) || identity.chain != source.ChainID || !strings.EqualFold(identity.genesis, source.GenesisHash) {
			return false
		}
	}
	return true
}

func witnessIndexInRange(index, from, to string) bool {
	n, err := strconv.ParseUint(index, 10, 64)
	a, b, rangeErr := governance.Range(from, to)
	return err == nil && rangeErr == nil && strconv.FormatUint(n, 10) == index && n >= a && n <= b
}

func bindWitnessHeader(ctx context.Context, tx pgx.Tx, network, dataset int64, source statewitness.Snapshot, point statewitness.Point) (string, error) {
	var actualNetwork int64
	var status, kind, visibility, chain, genesis, networkVisibility string
	var meta []byte
	err := tx.QueryRow(ctx, `SELECT d.network_id,d.status,d.kind,d.visibility,d.metadata,n.chain_id,n.genesis_hash,n.visibility FROM datasets d JOIN networks n ON n.id=d.network_id WHERE d.id=$1`, dataset).Scan(&actualNetwork, &status, &kind, &visibility, &meta, &chain, &genesis, &networkVisibility)
	if errors.Is(err, pgx.ErrNoRows) {
		return "source_unavailable", nil
	}
	if err != nil {
		return "", err
	}
	if actualNetwork != network || visibility != privacy.Visibility() || networkVisibility != privacy.Visibility() || chain != source.ChainID || !strings.EqualFold(genesis, source.GenesisHash) {
		return "network_mismatch", nil
	}
	if status != "complete" || kind != "range" && kind != "run" {
		return "source_unavailable", nil
	}
	var config struct {
		SHA string `json:"config_sha256"`
	}
	if json.Unmarshal(meta, &config) != nil || config.SHA != source.ConfigSHA {
		return "config_mismatch", nil
	}
	var hash string
	var raw []byte
	err = tx.QueryRow(ctx, `SELECT hash,fact FROM heights WHERE network_id=$1 AND index_=$2::numeric`, network, point.Index).Scan(&hash, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return "header_unavailable", nil
	}
	if err != nil {
		return "", err
	}
	var fact headers.Fact
	if json.Unmarshal(raw, &fact) != nil || hash != point.BlockHash || fact.Hash != hash || fact.Index != point.Index || fact.Number != point.Index || !sameWitnessEpoch(fact, point) {
		return "header_mismatch", nil
	}
	rows, err := tx.Query(ctx, `SELECT node,copy FROM header_copies WHERE dataset_id=$1 AND index_=$2::numeric AND hash=$3 ORDER BY node LIMIT 257`, dataset, point.Index, point.BlockHash)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var node string
		var raw []byte
		if err := rows.Scan(&node, &raw); err != nil {
			return "", err
		}
		var copy headers.Copy
		if json.Unmarshal(raw, &copy) != nil || copy.Index != point.Index || copy.Hash != hash || copy.Node != node {
			return "header_mismatch", nil
		}
		found = true
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if !found {
		return "header_unavailable", nil
	}
	return "matched", nil
}

func sameWitnessEpoch(fact headers.Fact, point statewitness.Point) bool {
	var info *types.EpochInfo
	return len(fact.EpochInfo) > 0 && json.Unmarshal(fact.EpochInfo, &info) == nil && statewitness.EpochDigest(info) == point.Epoch.SHA256
}

func (s *Store) GovernanceStateEvidence(ctx context.Context, dataset int64, index string) (result GovernanceStateEvidenceList, err error) {
	result = GovernanceStateEvidenceList{Index: index, Evidence: []GovernanceStateEvidence{}}
	n, err := strconv.ParseUint(index, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != index {
		return result, ErrGovernanceQuery
	}
	err = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var network int64
		if err := tx.QueryRow(ctx, `SELECT d.network_id FROM datasets d JOIN networks n ON n.id=d.network_id WHERE d.id=$1 AND d.kind='governance' AND d.status='complete' AND d.visibility=$2 AND n.visibility=$2`, dataset, privacy.Visibility()).Scan(&network); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		result, err = governanceStateEvidence(ctx, tx, network, dataset, index)
		return err
	})
	return result, err
}

func governanceStateEvidence(ctx context.Context, tx pgx.Tx, network, dataset int64, index string) (GovernanceStateEvidenceList, error) {
	result := GovernanceStateEvidenceList{Index: index, Evidence: []GovernanceStateEvidence{}}
	rows, err := tx.Query(ctx, `SELECT w.snapshot,w.header_dataset_id,w.header_source_id,w.info,p.point,(SELECT count(*) FROM governance_state_points all_points WHERE all_points.dataset_id=w.dataset_id AND all_points.snapshot=w.snapshot) FROM governance_state_points p JOIN governance_state_witnesses w USING(dataset_id,snapshot) JOIN datasets d ON d.id=p.dataset_id JOIN networks n ON n.id=d.network_id WHERE p.dataset_id=$1 AND p.index_=$2::numeric AND d.network_id=$3 AND d.kind='governance' AND d.status='complete' AND d.visibility=$4 AND n.visibility=$4 ORDER BY w.snapshot LIMIT 21`, dataset, index, network, privacy.Visibility())
	if err != nil {
		return result, err
	}
	for rows.Next() {
		entry := GovernanceStateEvidence{Witness: GovernanceStateWitness{DatasetID: dataset}, Status: "source_unavailable"}
		var info, point []byte
		if err := rows.Scan(&entry.Witness.Snapshot, &entry.Witness.HeadersDataset, &entry.Witness.HeaderSourceID, &info, &point, &entry.Witness.Points); err != nil {
			rows.Close()
			return result, err
		}
		if json.Unmarshal(info, &entry.Witness.Source) != nil || json.Unmarshal(point, &entry.Point) != nil || entry.Point.Index != index {
			rows.Close()
			return result, ErrStateWitnessBinding
		}
		result.Evidence = append(result.Evidence, entry)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	if len(result.Evidence) > 20 {
		result.Evidence = result.Evidence[:20]
		result.Truncated = true
	}
	for i := range result.Evidence {
		entry := &result.Evidence[i]
		var raw []byte
		if err := tx.QueryRow(ctx, `SELECT c.info FROM governance_captures c JOIN datasets d ON d.id=c.dataset_id WHERE d.id=$1 AND d.network_id=$2 AND d.kind='governance' AND d.status='complete' AND d.visibility=$3 AND lower(c.node)=lower($4)`, dataset, network, privacy.Visibility(), entry.Witness.Source.Node).Scan(&raw); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			return result, err
		}
		var capture GovernanceCapture
		if json.Unmarshal(raw, &capture) != nil || capture.DatasetID != dataset || !sameWitnessIdentity(capture, entry.Witness.Source) || !witnessIndexInRange(index, capture.From, capture.To) {
			continue
		}
		if entry.Witness.HeadersDataset == nil {
			continue
		}
		entry.Status, err = bindWitnessHeader(ctx, tx, network, *entry.Witness.HeadersDataset, entry.Witness.Source, entry.Point)
		if err != nil {
			return result, err
		}
	}
	return result, nil
}

func applyGovernanceState(epoch *GovernanceEpochEvidence, claim governance.Epoch, evidence GovernanceStateEvidenceList) {
	if len(evidence.Evidence) == 0 && !evidence.Truncated {
		return
	}
	epoch.ExecutionState = &evidence
	if evidence.Truncated {
		epoch.NoKeyStatus = "ambiguous_execution_keys"
		return
	}
	profiles := map[string]bool{}
	for _, entry := range evidence.Evidence {
		profile, _ := json.Marshal(struct {
			Config string                      `json:"config"`
			State  statewitness.ValidatorState `json:"state"`
		}{entry.Witness.Source.ConfigSHA, entry.Point.State})
		profiles[string(profile)] = true
	}
	if len(profiles) != 1 {
		epoch.NoKeyStatus = "ambiguous_execution_keys"
		return
	}
	for _, entry := range evidence.Evidence {
		if entry.Status != "matched" || entry.Point.Epoch.Keys != "matched" {
			return
		}
	}
	// Earlier normalization did not preserve whether an empty NoKey field
	// existed. A nonempty retained list proves presence; an older empty list
	// cannot be promoted from missing to a verified empty claim.
	if evidence.Index == "0" || epoch.Status != "available" || !claim.NoKeyReported && len(claim.NoKey) == 0 {
		return
	}
	without := evidence.Evidence[0].Point.State.WithoutKeys
	epoch.NoKeyStatus = "mismatch_execution_keys"
	if len(without) != len(claim.NoKey) {
		return
	}
	for i := range without {
		if !strings.EqualFold(without[i], claim.NoKey[i]) {
			return
		}
	}
	epoch.NoKeyStatus = "verified_execution_keys"
}
