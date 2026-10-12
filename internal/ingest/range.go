package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/headers"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft/chain/validator"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

type RangeOptions struct {
	Name, Node, NetworkName string
	From, To                uint64
	Config                  []byte
	Source                  *headers.Source
	Progress                func(int64, time.Duration)
}
type RangeResult struct {
	DatasetID, NetworkID, Headers int64
	Elapsed                       time.Duration
}

// Range imports complete batches and leaves failures on the dataset. Repeating
// the same immutable range resumes it and does not duplicate network facts.
func Range(ctx context.Context, s *store.Store, o RangeOptions) (res RangeResult, err error) {
	if o.Name == "" || o.Node == "" || o.To < o.From || o.To == ^uint64(0) || o.To-o.From >= 1_000_000 {
		return res, errors.New("range needs a name, node, and 1..1000000 indices with room for the child")
	}
	cfg, err := types.ParseChainConfig(o.Config)
	if err != nil {
		return res, err
	}
	if cfg.ChainID == nil {
		return res, errors.New("configuration needs chainId")
	}
	src := o.Source
	if src == nil {
		return res, errors.New("range needs a header source")
	}
	src.Context = ctx
	g, err := src.Read(0)
	if err != nil {
		return res, err
	}
	if src.RPC != nil {
		var id string
		if err = src.RPC.Call(ctx, &id, "eth_chainId"); err != nil {
			return res, err
		}
		if id != "0x"+cfg.ChainID.Text(16) {
			return res, errors.New("RPC chain ID differs from configuration")
		}
	}
	_, length := validator.EpochSchedule(cfg, types.HeightFromUint64(o.From))
	if length > 1_000_000 {
		return res, errors.New("epoch window exceeds one million headers")
	}
	src.CacheLimit = int(length*3) + 200
	sum := sha256.Sum256(o.Config)
	meta, _ := json.Marshal(map[string]string{"from": strconv.FormatUint(o.From, 10), "to": strconv.FormatUint(o.To, 10), "config_sha256": hex.EncodeToString(sum[:]), "genesis_hash": codec.BlockHash(g).Hex()})
	d, release, err := s.BeginRange(ctx, store.NetworkKey{ChainID: cfg.ChainID.String(), GenesisHash: codec.BlockHash(g).Hex(), Name: o.NetworkName}, o.Name, meta)
	if err != nil {
		return res, err
	}
	defer release()
	res.DatasetID, res.NetworkID = d.ID, d.NetworkID
	start := time.Now()
	defer func() {
		res.Elapsed = time.Since(start)
		detail := ""
		if err != nil {
			detail = "range import failed; see local command output"
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if endErr := s.FinishRange(cleanup, d.ID, res.Headers, detail); err == nil {
			err = endErr
		}
	}()
	// Warm the epoch window before the first analyzed header. Dependency headers
	// are fetched on demand; only the requested range and its child are persisted.
	warm := o.From
	if warm > length*2 {
		warm -= length * 2
	} else {
		warm = 0
	}
	for from := warm; from <= o.To+1; {
		to := from + 99
		if to < from || to > o.To+1 {
			to = o.To + 1
		}
		if err = src.Prefetch(from, to); err != nil {
			return res, err
		}
		facts := []headers.Fact{}
		copies := []headers.Copy{}
		for n := from; ; n++ {
			if n >= o.From {
				f, c, e := headers.Analyze(src, cfg, n, o.Node)
				if e != nil {
					err = fmt.Errorf("header %d: %w", n, e)
					return res, err
				}
				facts = append(facts, f)
				copies = append(copies, c)
			}
			if n == to {
				break
			}
		}
		count := int64(0)
		for _, f := range facts {
			if f.Index != strconv.FormatUint(o.To+1, 10) {
				count++
			}
		}
		if len(facts) > 0 {
			if err = s.PutHeaders(ctx, d.ID, d.NetworkID, facts, copies, res.Headers+count); err != nil {
				return res, err
			}
			res.Headers += count
		}
		if o.Progress != nil {
			o.Progress(res.Headers, time.Since(start))
		}
		if to == o.To+1 {
			break
		}
		from = to + 1
	}
	return res, nil
}
