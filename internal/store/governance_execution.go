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
	"github.com/0xmhha/wbft-analyzer/internal/source/executionwitness"
	"github.com/0xmhha/wbft-analyzer/internal/source/governance"
	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/jackc/pgx/v5"
)

var ErrExecutionWitnessBinding = errors.New("execution witness has no matching completed governance and canonical sources")

type GovernanceExecutionWitness struct {
	DatasetID      int64                       `json:"dataset_id"`
	Snapshot       string                      `json:"snapshot"`
	HeadersDataset *int64                      `json:"headers_dataset"`
	HeaderSourceID int64                       `json:"header_source_id"`
	Source         executionwitness.Projection `json:"source"`
	Blocks         int                         `json:"blocks"`
	Transactions   int                         `json:"transactions"`
}

// Only the loader's opaque result may cross the persistence boundary. Source
// capture data is immutable and never rewritten to agree with VM execution.
func (s *Store) PutGovernanceExecutionWitness(ctx context.Context, dataset, headerDataset int64, bundle executionwitness.Bundle) (GovernanceExecutionWitness, error) {
	var result GovernanceExecutionWitness
	projection := bundle.Projection()
	source := projection.Report.Source
	if dataset < 1 || headerDataset < 1 || dataset == headerDataset || projection.Report.Protocol != executionwitness.Protocol || len(source.Blocks) < 1 || len(source.Blocks) > executionwitness.MaxBlocks || len(projection.Report.Transactions) > executionwitness.MaxTransactions || projection.Verifier.SHA256 == "" {
		return result, ErrExecutionWitnessBinding
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
		Header int64                       `json:"headers_dataset"`
		Source executionwitness.Projection `json:"source"`
	}{headerDataset, projection})
	if err != nil {
		return result, err
	}
	sum := sha256.Sum256(raw)
	result = GovernanceExecutionWitness{DatasetID: dataset, Snapshot: hex.EncodeToString(sum[:]), HeadersDataset: &headerDataset, HeaderSourceID: headerDataset, Source: projection, Blocks: len(source.Blocks), Transactions: len(projection.Report.Transactions)}
	result.Source.Report.Source.Blocks = []executionwitness.BlockEvidence{}
	result.Source.Report.Transactions = []executionwitness.Transaction{}
	info, err := json.Marshal(result)
	if err != nil {
		return result, err
	}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		network, capture, err := executionCapture(ctx, tx, dataset, true)
		if err != nil {
			return err
		}
		if !executionIdentity(capture, source) || !executionRange(capture, source.Blocks) {
			return ErrExecutionWitnessBinding
		}
		tag, err := tx.Exec(ctx, `INSERT INTO governance_execution_witnesses(dataset_id,snapshot,header_dataset_id,header_source_id,info) VALUES($1,$2,$3,$3,$4) ON CONFLICT(dataset_id,snapshot) DO UPDATE SET snapshot=governance_execution_witnesses.snapshot WHERE governance_execution_witnesses.info=EXCLUDED.info AND governance_execution_witnesses.header_dataset_id=EXCLUDED.header_dataset_id AND governance_execution_witnesses.header_source_id=EXCLUDED.header_source_id`, dataset, result.Snapshot, headerDataset, info)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrExecutionWitnessBinding
		}
		for _, block := range source.Blocks {
			raw, err := json.Marshal(block)
			if err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `INSERT INTO governance_execution_blocks(dataset_id,snapshot,index_,block) VALUES($1,$2,$3::numeric,$4) ON CONFLICT DO NOTHING`, dataset, result.Snapshot, block.Index, raw); err != nil {
				return err
			}
		}
		for _, point := range projection.Report.Transactions {
			raw, err := json.Marshal(point)
			if err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `INSERT INTO governance_execution_transactions(dataset_id,snapshot,index_,tx_ordinal,point) VALUES($1,$2,$3::numeric,$4,$5) ON CONFLICT DO NOTHING`, dataset, result.Snapshot, point.Index, point.Ordinal, raw); err != nil {
				return err
			}
		}
		binding, err := bindExecutionHeaders(ctx, tx, network, result)
		if err != nil {
			return err
		}
		if binding != "matched" {
			return ErrExecutionWitnessBinding
		}
		return nil
	})
	if err != nil {
		return GovernanceExecutionWitness{}, err
	}
	return result, nil
}

func executionCapture(ctx context.Context, tx pgx.Tx, id int64, lock bool) (int64, GovernanceCapture, error) {
	var network int64
	var raw []byte
	var node string
	suffix := ""
	if lock {
		suffix = " FOR UPDATE OF d"
	}
	err := tx.QueryRow(ctx, `SELECT d.network_id,c.node,c.info FROM datasets d JOIN networks n ON n.id=d.network_id JOIN governance_captures c ON c.dataset_id=d.id WHERE d.id=$1 AND d.kind='governance' AND d.status='complete' AND d.visibility=$2 AND n.visibility=$2`+suffix, id, privacy.Visibility()).Scan(&network, &node, &raw)
	var capture GovernanceCapture
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, capture, ErrNotFound
	}
	if err != nil {
		return 0, capture, err
	}
	if json.Unmarshal(raw, &capture) != nil || capture.DatasetID != id || !strings.EqualFold(node, capture.Before.Address) {
		return 0, capture, ErrExecutionWitnessBinding
	}
	return network, capture, nil
}

func executionIdentity(capture GovernanceCapture, source executionwitness.Snapshot) bool {
	for _, id := range []governance.Identity{capture.Before, capture.After} {
		if !strings.EqualFold(id.Address, source.Node) || id.ChainID != source.ChainID || !strings.EqualFold(id.GenesisHash, source.GenesisHash) {
			return false
		}
	}
	return true
}
func executionRange(capture GovernanceCapture, blocks []executionwitness.BlockEvidence) bool {
	_, to, err := governance.Range(capture.From, capture.To)
	if err != nil || len(blocks) == 0 {
		return false
	}
	last, err := strconv.ParseUint(blocks[len(blocks)-1].Index, 10, 64)
	return err == nil && blocks[0].Index == "0" && blocks[len(blocks)-1].Index == strconv.FormatUint(last, 10) && last >= to
}

// Every replayed block stays bound to the explicitly selected canonical source.
// A different surviving source must not silently replace a removed dependency.
func bindExecutionHeaders(ctx context.Context, tx pgx.Tx, network int64, w GovernanceExecutionWitness) (string, error) {
	if w.HeadersDataset == nil {
		return "source_unavailable", nil
	}
	var actualNetwork int64
	var status, kind, visibility, networkVisibility, chain, genesis string
	var meta []byte
	err := tx.QueryRow(ctx, `SELECT d.network_id,d.status,d.kind,d.visibility,d.metadata,n.visibility,n.chain_id,n.genesis_hash FROM datasets d JOIN networks n ON n.id=d.network_id WHERE d.id=$1`, *w.HeadersDataset).Scan(&actualNetwork, &status, &kind, &visibility, &meta, &networkVisibility, &chain, &genesis)
	if errors.Is(err, pgx.ErrNoRows) {
		return "source_unavailable", nil
	}
	if err != nil {
		return "", err
	}
	source := w.Source.Report.Source
	if actualNetwork != network || visibility != privacy.Visibility() || networkVisibility != privacy.Visibility() || chain != source.ChainID || !strings.EqualFold(genesis, source.GenesisHash) {
		return "network_mismatch", nil
	}
	if status != "complete" || kind != "range" && kind != "run" {
		return "source_unavailable", nil
	}
	var config struct {
		SHA string `json:"config_sha256"`
	}
	if json.Unmarshal(meta, &config) != nil || config.SHA != source.ConfigSHA256 {
		return "config_mismatch", nil
	}
	rows, err := tx.Query(ctx, `SELECT b.index_::text,b.block,h.hash,h.fact,EXISTS(SELECT 1 FROM header_copies c WHERE c.dataset_id=$4 AND c.index_=b.index_ AND c.hash=b.block->>'hash' AND c.copy->>'index'=b.index_::text AND c.copy->>'hash'=c.hash AND c.copy->>'node'=c.node) FROM governance_execution_blocks b LEFT JOIN heights h ON h.network_id=$3 AND h.index_=b.index_ WHERE b.dataset_id=$1 AND b.snapshot=$2 ORDER BY b.index_`, w.DatasetID, w.Snapshot, network, *w.HeadersDataset)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	count := 0
	previous := ""
	for rows.Next() {
		var index string
		var raw, factRaw []byte
		var hash *string
		var copied bool
		if err := rows.Scan(&index, &raw, &hash, &factRaw, &copied); err != nil {
			return "", err
		}
		var block executionwitness.BlockEvidence
		if json.Unmarshal(raw, &block) != nil || block.Index != index || index != strconv.Itoa(count) || count > 0 && block.Parent != previous {
			return "header_mismatch", nil
		}
		if count == 0 {
			if block.Hash != source.GenesisHash {
				return "header_mismatch", nil
			}
		} else {
			if hash == nil || !copied {
				return "header_unavailable", nil
			}
			var fact headers.Fact
			if json.Unmarshal(factRaw, &fact) != nil || fact.Index != index || fact.Number != index || fact.Hash != block.Hash || *hash != block.Hash || fact.ParentHash != block.Parent {
				return "header_mismatch", nil
			}
		}
		previous = block.Hash
		count++
		if count > executionwitness.MaxBlocks {
			return "header_mismatch", nil
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if count != w.Blocks || count < 1 {
		return "header_mismatch", nil
	}
	return "matched", nil
}
