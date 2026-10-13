package store

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/0xmhha/wbft/types"
	"github.com/jackc/pgx/v5"
)

type Dataset struct {
	CopyNodes []string        `json:"copy_nodes"`
	Nodes     []string        `json:"nodes"`
	ID        int64           `json:"id"`
	NetworkID int64           `json:"network_id"`
	Name      string          `json:"name"`
	Kind      string          `json:"kind"`
	Status    string          `json:"status"`
	Progress  int64           `json:"progress"`
	Error     string          `json:"error"`
	Metadata  json.RawMessage `json:"metadata"`
	UpdatedAt time.Time       `json:"updated_at"`
}

func scanDataset(r pgx.CollectableRow) (Dataset, error) {
	var d Dataset
	err := r.Scan(&d.ID, &d.NetworkID, &d.Name, &d.Kind, &d.Status, &d.Progress, &d.Error, &d.Metadata, &d.UpdatedAt, &d.Nodes, &d.CopyNodes)
	return d, err
}

const datasetColumns = `id,network_id,name,kind,status,progress,error,metadata,updated_at,coalesce((SELECT array_agg(DISTINCT hc.node ORDER BY hc.node) FROM (SELECT node FROM header_copies WHERE dataset_id=datasets.id UNION SELECT node FROM log_inputs WHERE dataset_id=datasets.id UNION SELECT node FROM message_inputs WHERE dataset_id=datasets.id UNION SELECT node FROM observation_captures WHERE dataset_id=datasets.id) hc), ARRAY[]::text[]),coalesce((SELECT array_agg(DISTINCT node ORDER BY node) FROM header_copies WHERE dataset_id=datasets.id),ARRAY[]::text[])`

func (s *Store) Datasets(ctx context.Context, networkID int64) ([]Dataset, error) {
	r, err := s.pool.Query(ctx, `SELECT `+datasetColumns+` FROM datasets WHERE network_id=$1 ORDER BY id`, networkID)
	if err != nil {
		return nil, err
	}
	return collect(r, scanDataset)
}

// BeginRange protects the dataset with a session advisory lock. A stale
// importing state can resume only when its old connection no longer holds it.
func (s *Store) BeginRange(ctx context.Context, k NetworkKey, name string, metadata json.RawMessage) (Dataset, func(), error) {
	return s.beginDataset(ctx, k, name, "range", metadata)
}

func (s *Store) BeginRun(ctx context.Context, k NetworkKey, name string, metadata json.RawMessage) (Dataset, func(), error) {
	return s.beginDataset(ctx, k, name, "run", metadata)
}

func (s *Store) beginDataset(ctx context.Context, k NetworkKey, name, kind string, metadata json.RawMessage) (Dataset, func(), error) {
	var nid, id int64
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO networks(chain_id,genesis_hash,name,visibility) VALUES($1,$2,$3,'public') ON CONFLICT(chain_id,genesis_hash) DO UPDATE SET chain_id=EXCLUDED.chain_id RETURNING id`, k.ChainID, k.GenesisHash, k.Name).Scan(&nid); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO datasets(network_id,name,kind,visibility,metadata) VALUES($1,$2,$3,'public',$4) ON CONFLICT(name) DO UPDATE SET name=EXCLUDED.name RETURNING id`, nid, name, kind, metadata).Scan(&id)
	})
	if err != nil {
		return Dataset{}, nil, err
	}
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return Dataset{}, nil, err
	}
	var locked bool
	if err = conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended('wbft-analyzer:range:'||current_schema()||':'||$1::bigint::text,0))`, id).Scan(&locked); err != nil || !locked {
		conn.Release()
		if err == nil {
			err = errors.New("dataset is already importing")
		}
		return Dataset{}, nil, err
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := conn.Exec(cleanup, `SELECT pg_advisory_unlock(hashtextextended('wbft-analyzer:range:'||current_schema()||':'||$1::bigint::text,0))`, id); err != nil {
				_ = conn.Conn().Close(cleanup)
			}
			conn.Release()
		})
	}
	rows, err := conn.Query(ctx, `SELECT `+datasetColumns+` FROM datasets WHERE id=$1`, id)
	if err != nil {
		release()
		return Dataset{}, nil, err
	}
	d, err := one(rows, scanDataset)
	if err != nil {
		release()
		return d, nil, err
	}
	var a, b any
	_ = json.Unmarshal(d.Metadata, &a)
	_ = json.Unmarshal(metadata, &b)
	aa, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	if d.NetworkID != nid || d.Kind != kind || !bytes.Equal(aa, bb) {
		release()
		return d, nil, errors.New("dataset name already has a different network, kind or input configuration")
	}
	if _, err = conn.Exec(ctx, `UPDATE datasets SET status='importing',error='',updated_at=now() WHERE id=$1`, id); err != nil {
		release()
		return d, nil, err
	}
	return d, release, nil
}
func (s *Store) FinishRange(ctx context.Context, id int64, progress int64, detail string) error {
	state := "complete"
	if detail != "" {
		state = "failed"
	}
	_, err := s.pool.Exec(ctx, `UPDATE datasets SET status=$2,progress=$3,error=$4,updated_at=now() WHERE id=$1`, id, state, progress, detail)
	return err
}

// PutHeaders is atomic per bounded batch. An existing index with different
// canonical content is an error, never an implicit reorg or overwrite.
func (s *Store) PutHeaders(ctx context.Context, datasetID, networkID int64, facts []headers.Fact, copies []headers.Copy, progress int64) error {
	if len(facts) != len(copies) {
		return errors.New("header/copy length differs")
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		for i, f := range facts {
			raw, err := json.Marshal(f)
			if err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, `INSERT INTO heights(network_id,index_,hash,fact) VALUES($1,$2::numeric,$3,$4) ON CONFLICT(network_id,index_) DO UPDATE SET hash=heights.hash WHERE heights.hash=EXCLUDED.hash AND heights.fact=EXCLUDED.fact`, networkID, f.Index, f.Hash, raw)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return fmt.Errorf("canonical header conflict at %s", f.Index)
			}
			seen := map[int64]bool{}
			for _, xs := range [][]int64{f.PrevPrepared, f.PrevCommitted} {
				for _, v := range xs {
					seen[v] = true
				}
			}
			for idx := range seen {
				p, q := hasIndex(f.PrevPrepared, idx), hasIndex(f.PrevCommitted, idx)
				if _, err := tx.Exec(ctx, `INSERT INTO seals(network_id,index_,validator_idx,prev_prepared,prev_committed) VALUES($1,$2::numeric,$3,$4,$5) ON CONFLICT DO NOTHING`, networkID, f.Index, idx, p, q); err != nil {
					return err
				}
			}
			if string(f.EpochInfo) != "null" && len(f.EpochInfo) > 0 {
				if _, err := tx.Exec(ctx, `INSERT INTO epochs(network_id,index_,info,check_,detail) VALUES($1,$2::numeric,$3,$4,$5) ON CONFLICT DO NOTHING`, networkID, f.Index, f.EpochInfo, f.EpochCheck, f.EpochDetail); err != nil {
					return err
				}
			}
			c := copies[i]
			data, err := json.Marshal(c)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO header_copies(dataset_id,node,index_,hash,copy) VALUES($1,$2,$3::numeric,$4,$5) ON CONFLICT(dataset_id,node,hash) DO UPDATE SET copy=EXCLUDED.copy`, datasetID, c.Node, c.Index, c.Hash, data); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `UPDATE datasets SET progress=$2,updated_at=now() WHERE id=$1`, datasetID, progress)
		return err
	})
}
func hasIndex(xs []int64, n int64) bool {
	for _, x := range xs {
		if x == n {
			return true
		}
	}
	return false
}

// HeaderRows returns at most 1024 heights, with an optional node's copy and
// the next height's immutable previous seals. The next height is read even
// when it is outside the displayed window.
func (s *Store) HeaderRows(ctx context.Context, networkID int64, from, to string, datasetID *int64, node string) ([]headers.Row, error) {
	var result []headers.Row
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if datasetID != nil {
			var kind string
			if e := tx.QueryRow(ctx, `SELECT kind FROM datasets WHERE id=$1 AND network_id=$2`, *datasetID, networkID).Scan(&kind); e != nil {
				return e
			}
			if kind == "observations" {
				if _, e := readObservationHeaderIndex(ctx, tx, *datasetID); e != nil {
					return e
				}
			}
		}
		rows, err := tx.Query(ctx, `SELECT h.fact,c.fact,hc.copy FROM heights h LEFT JOIN heights c ON c.network_id=h.network_id AND c.index_=h.index_+1 LEFT JOIN header_copies hc ON hc.dataset_id=$4 AND hc.node=$5 AND hc.index_=h.index_ WHERE h.network_id=$1 AND h.index_ BETWEEN $2::numeric AND $3::numeric ORDER BY h.index_ LIMIT 1024`, networkID, from, to, datasetID, node)
		if err != nil {
			return err
		}
		result, err = collect(rows, func(r pgx.CollectableRow) (headers.Row, error) {
			var raw, child, copy []byte
			if err := r.Scan(&raw, &child, &copy); err != nil {
				return headers.Row{}, err
			}
			var f headers.Fact
			if err := json.Unmarshal(raw, &f); err != nil {
				return headers.Row{}, err
			}
			var ch *headers.Fact
			var c *headers.Copy
			if len(child) > 0 {
				if err := json.Unmarshal(child, &ch); err != nil {
					return headers.Row{}, err
				}
			}
			if len(copy) > 0 {
				if err := json.Unmarshal(copy, &c); err != nil {
					return headers.Row{}, err
				}
			}
			p, err := strconv.ParseUint(f.Policy, 10, 64)
			if err != nil {
				return headers.Row{}, err
			}
			var last types.Address
			if err := last.UnmarshalText([]byte(f.LastProposer)); err != nil {
				return headers.Row{}, err
			}
			return headers.Derive(f, ch, c, &types.ProposerPolicy{ID: p}, last)
		})
		return err
	})
	return result, err
}

type HeaderBounds struct {
	From  *string `json:"from"`
	To    *string `json:"to"`
	Count int64   `json:"count"`
	Bytes int64   `json:"bytes"`
}

func (s *Store) HeaderBounds(ctx context.Context, networkID int64) (HeaderBounds, error) {
	var b HeaderBounds
	err := s.pool.QueryRow(ctx, `SELECT min(index_)::text,max(index_)::text,count(*),coalesce(sum(pg_column_size(fact)),0) FROM heights WHERE network_id=$1`, networkID).Scan(&b.From, &b.To, &b.Count, &b.Bytes)
	return b, err
}

type EpochCandidate struct {
	Index          int64   `json:"index"`
	Address        string  `json:"address"`
	Diligence      string  `json:"diligence"`
	ValidatorOrder *int64  `json:"validator_order"`
	BLSKey         *string `json:"bls_key"`
}
type Epoch struct {
	ChangesKnown bool             `json:"changes_known"`
	Index        string           `json:"index"`
	Info         json.RawMessage  `json:"info"`
	Check        string           `json:"check"`
	Detail       string           `json:"detail"`
	Candidates   []EpochCandidate `json:"candidates"`
	Added        []string         `json:"added"`
	Removed      []string         `json:"removed"`
}

func describeEpoch(e *Epoch, prior json.RawMessage) error {
	var info types.EpochInfo
	if err := json.Unmarshal(e.Info, &info); err != nil {
		return err
	}
	e.Candidates = []EpochCandidate{}
	e.Added = []string{}
	e.Removed = []string{}
	for i, c := range info.Candidates {
		x := EpochCandidate{Index: int64(i), Address: c.Addr.Hex(), Diligence: strconv.FormatUint(c.Diligence, 10)}
		for order, index := range info.Validators {
			if int(index) == i {
				if order >= len(info.BLSPublicKeys) {
					return errors.New("epoch keys are incomplete")
				}
				n := int64(order)
				key := "0x" + hex.EncodeToString(info.BLSPublicKeys[order])
				x.ValidatorOrder = &n
				x.BLSKey = &key
			}
		}
		e.Candidates = append(e.Candidates, x)
	}
	old := types.EpochInfo{}
	if len(prior) > 0 {
		if err := json.Unmarshal(prior, &old); err != nil {
			return err
		}
	}
	e.ChangesKnown = len(prior) > 0 || e.Index == "0"
	if !e.ChangesKnown {
		return nil
	}
	current, previous := map[string]bool{}, map[string]bool{}
	for _, a := range info.ValidatorAddresses() {
		current[a.Hex()] = true
	}
	for _, a := range old.ValidatorAddresses() {
		previous[a.Hex()] = true
	}
	for _, a := range info.ValidatorAddresses() {
		if !previous[a.Hex()] {
			e.Added = append(e.Added, a.Hex())
		}
	}
	for _, a := range old.ValidatorAddresses() {
		if !current[a.Hex()] {
			e.Removed = append(e.Removed, a.Hex())
		}
	}
	return nil
}

func (s *Store) Epochs(ctx context.Context, networkID int64, from, to string) ([]Epoch, error) {
	r, err := s.pool.Query(ctx, `SELECT e.index_::text,e.info,e.check_,e.detail,(SELECT p.info FROM epochs p WHERE p.network_id=e.network_id AND p.index_<e.index_ ORDER BY p.index_ DESC LIMIT 1) FROM epochs e WHERE e.network_id=$1 AND e.index_ BETWEEN $2::numeric AND $3::numeric ORDER BY e.index_ LIMIT 1024`, networkID, from, to)
	if err != nil {
		return nil, err
	}
	return collect(r, func(r pgx.CollectableRow) (Epoch, error) {
		var e Epoch
		var prior json.RawMessage
		err := r.Scan(&e.Index, &e.Info, &e.Check, &e.Detail, &prior)
		if err == nil {
			err = describeEpoch(&e, prior)
		}
		return e, err
	})
}
