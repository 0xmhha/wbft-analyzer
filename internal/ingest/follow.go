package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/observe"
	"github.com/0xmhha/wbft-analyzer/internal/source/rpc"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/observe/participation"
	"github.com/0xmhha/wbft/types"
)

var ErrFollowIdentity = errors.New("follow network, node, configuration or parent identity changed")
var ErrFollowIncomplete = errors.New("follow participation is incomplete or summary changed; cursor retained")

type FollowOptions struct {
	Name, Node, NetworkName string
	From                    uint64
	Config                  []byte
	RPC                     *rpc.Client
}
type Follower struct {
	Store    *store.Store
	Options  FollowOptions
	Dataset  store.Dataset
	Address  string
	Identity store.NetworkKey
	release  func()
}
type FollowResult struct {
	DatasetID    int64  `json:"dataset_id"`
	From         uint64 `json:"from_index"`
	To           uint64 `json:"to_index"`
	Next         string `json:"next_index"`
	Headers      int64  `json:"headers"`
	Observations int64  `json:"observations_dataset"`
}

// OpenFollower binds a restartable source without storing its RPC URL. Native
// metadata and historical claims retain their independent collection semantics.
func OpenFollower(ctx context.Context, s *store.Store, o FollowOptions) (f *Follower, err error) {
	defer func() {
		if err != nil {
			err = &followFailure{stage: "open_source", err: err}
		}
	}()
	if !logs.Identifier(o.Name) || !logs.Identifier(o.Node) || o.RPC == nil || o.From == 0 || o.From == ^uint64(0) {
		return nil, errors.New("follow needs valid source labels, RPC and a start index with room for a child")
	}
	cfg, e := types.ParseChainConfig(o.Config)
	if e != nil || cfg.ChainID == nil {
		return nil, errors.New("follow needs a valid chain configuration")
	}
	src := &headers.Source{Context: ctx, RPC: o.RPC}
	g, e := src.Read(0)
	if e != nil {
		return nil, e
	}
	var chain string
	if e = o.RPC.Call(ctx, &chain, "eth_chainId"); e != nil {
		return nil, e
	}
	if chain != "0x"+cfg.ChainID.Text(16) {
		return nil, ErrFollowIdentity
	}
	a, e := observe.Fetch(ctx, o.RPC, "0", "0")
	if e != nil {
		return nil, e
	}
	snap, e := observe.Normalize(a)
	if e != nil {
		return nil, e
	}
	genesis := codec.BlockHash(g).Hex()
	if snap.Node.ChainID.Cmp(cfg.ChainID) != 0 || snap.Node.GenesisHash.String() != genesis {
		return nil, ErrFollowIdentity
	}
	parent := types.Hash{}.Hex()
	if o.From > 0 {
		h, e := src.Read(o.From - 1)
		if e != nil {
			return nil, e
		}
		parent = codec.BlockHash(h).Hex()
	}
	sum := sha256.Sum256(o.Config)
	address := strings.ToLower(snap.Node.Address.String())
	meta, _ := json.Marshal(map[string]string{"version": "wbft-follow/1", "from": strconv.FormatUint(o.From, 10), "node": o.Node, "address": address, "config_sha256": hex.EncodeToString(sum[:]), "initial_parent": parent})
	d, release, e := s.BeginFollow(ctx, store.NetworkKey{ChainID: cfg.ChainID.String(), GenesisHash: genesis, Name: o.NetworkName}, o.Name, meta, o.From, parent)
	if e != nil {
		return nil, fmt.Errorf("%w: %v", ErrFollowIdentity, e)
	}
	return &Follower{Store: s, Options: o, Dataset: d, Address: address, Identity: store.NetworkKey{ChainID: cfg.ChainID.String(), GenesisHash: genesis}, release: release}, nil
}
func (f *Follower) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = f.Store.StopFollow(ctx, f.Dataset.ID)
	f.release()
}

// Step captures at most 100 canonical indices and leaves a carrier available.
// Full heights are obtained from the headers, never reconstructed from indices.
func (f *Follower) Step(ctx context.Context) (res FollowResult, err error) {
	stage := "read_cursor"
	defer func() {
		if err != nil {
			err = &followFailure{stage: stage, err: err}
		}
	}()
	res.DatasetID = f.Dataset.ID
	cursor, e := f.Store.FollowCursor(ctx, f.Dataset.ID)
	if e != nil {
		return res, e
	}
	res.Next = cursor.Next
	from, e := strconv.ParseUint(cursor.Next, 10, 64)
	if e != nil {
		return res, e
	}
	var encoded string
	stage = "read_head"
	if e = f.Options.RPC.Call(ctx, &encoded, "eth_blockNumber"); e != nil {
		return res, e
	}
	head, ok := new(big.Int).SetString(strings.TrimPrefix(encoded, "0x"), 16)
	if !strings.HasPrefix(encoded, "0x") || !ok || head.Sign() < 0 || head.BitLen() > 512 {
		return res, errors.New("invalid follow head")
	}
	index := head.Uint64()
	if from > 0 && index < from-1 {
		return res, ErrFollowIdentity
	}
	if index <= from {
		return res, nil
	}
	to := min(index-1, from+min(uint64(99), ^uint64(0)-from))
	src := &headers.Source{Context: ctx, RPC: f.Options.RPC}
	stage = "read_genesis"
	g, e := src.Read(0)
	if e != nil {
		return res, e
	}
	if codec.BlockHash(g).Hex() != f.Identity.GenesisHash {
		return res, ErrFollowIdentity
	}
	stage = "read_current_header"
	current, e := src.Read(index)
	if e != nil {
		return res, e
	}
	if current.Number.Big().Cmp(head) != 0 {
		return res, ErrFollowIdentity
	}
	if from > 0 {
		stage = "read_parent_header"
		h, e := src.Read(from - 1)
		if e != nil {
			return res, e
		}
		if codec.BlockHash(h).Hex() != cursor.ParentHash {
			return res, ErrFollowIdentity
		}
	}
	stage = "prefetch_headers"
	if e = src.Prefetch(from, to); e != nil {
		return res, e
	}
	stage = "read_first_header"
	first, e := src.Read(from)
	if e != nil {
		return res, e
	}
	if first.ParentHash.Hex() != cursor.ParentHash {
		return res, ErrFollowIdentity
	}
	stage = "validate_heights"
	for n := from + 1; n <= to; n++ {
		h, e := src.Read(n)
		if e != nil {
			return res, e
		}
		expected := new(big.Int).Add(first.Number.Big(), new(big.Int).SetUint64(n-from))
		if h.Number.Big().Cmp(expected) != 0 {
			to = n - 1
			break
		}
	}
	stage = "read_last_header"
	last, e := src.Read(to)
	if e != nil {
		return res, e
	}
	stage = "capture_observations"
	a, e := observe.Fetch(ctx, f.Options.RPC, first.Number.String(), last.Number.String())
	if e != nil {
		return res, e
	}
	stage = "normalize_observations"
	snap, e := observe.Normalize(a)
	if e != nil {
		return res, e
	}
	if strings.ToLower(snap.Node.Address.String()) != f.Address || snap.Node.GenesisHash.String() != f.Identity.GenesisHash || snap.Node.ChainID.String() != f.Identity.ChainID {
		return res, ErrFollowIdentity
	}
	stage = "validate_observations"
	if e = completeFollow(snap, src, from, to); e != nil {
		return res, e
	}
	// Companion names bind immutable scopes/content. A crash before CommitFollow
	// can replay the batch without replacing an earlier observation snapshot.
	prefix := fmt.Sprintf("follow-%d-%d-%d", f.Dataset.ID, from, to)
	stage = "ingest_headers"
	r, e := Range(ctx, f.Store, RangeOptions{Name: prefix + "-headers", Node: f.Options.Node, NetworkName: f.Options.NetworkName, From: from, To: to, Config: f.Options.Config, Source: src})
	if e != nil {
		return res, e
	}
	stage = "encode_observations"
	raw, e := json.Marshal(a)
	if e != nil {
		return res, e
	}
	sum := sha256.Sum256(raw)
	sha := hex.EncodeToString(sum[:])
	stage = "ingest_observations"
	o, e := Observations(ctx, f.Store, fmt.Sprintf("follow-%d-observation-%s", f.Dataset.ID, sha), "rpc", sha, a)
	if e != nil {
		return res, e
	}
	stage = "commit_cursor"
	if e = f.Store.CommitFollow(ctx, f.Dataset.ID, from, to, cursor.ParentHash, codec.BlockHash(last).Hex(), r.DatasetID, o.DatasetID); e != nil {
		return res, e
	}
	res.From = from
	res.To = to
	res.Headers = int64(to-from) + 1
	res.Observations = o.DatasetID
	res.Next = strconv.FormatUint(to+1, 10)
	return res, nil
}
func completeFollow(snap observe.Snapshot, src *headers.Source, from, to uint64) error {
	if snap.RoundChanges != nil && snap.RoundChanges.Status == "different" {
		return ErrFollowIncomplete
	}
	if snap.Comparison.Status != "match" || snap.Comparison.Computed == nil || snap.Comparison.Computed.Gaps != 0 {
		return ErrFollowIncomplete
	}
	for _, c := range snap.Calls {
		if c.Method == "wbft_participation" && c.Status == "available" {
			var rows []participation.Record
			if e := json.Unmarshal(c.Data, &rows); e != nil {
				return e
			}
			if uint64(len(rows)) != to-from+1 {
				return ErrFollowIncomplete
			}
			for i, r := range rows {
				h, e := src.Read(from + uint64(i))
				if e != nil {
					return e
				}
				if r.Gap {
					return ErrFollowIncomplete
				}
				if r.Height != h.Number.String() || r.Hash != codec.BlockHash(h).Hex() {
					return ErrFollowIdentity
				}
			}
			return nil
		}
	}
	return ErrFollowIncomplete
}
