// Package headers provides a bounded read-only WBFT chain from RPC or RLP files.
package headers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/0xmhha/wbft-analyzer/internal/source/rpc"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/types"
)

type Source struct {
	Context    context.Context
	RPC        *rpc.Client
	Blocks     string
	CacheLimit int
	Err        error
	cache      map[uint64]*types.Header
	order      []uint64
	head       *types.Header
}

func (s *Source) remember(index uint64, h *types.Header) {
	if s.cache == nil {
		s.cache = map[uint64]*types.Header{}
	}
	if _, ok := s.cache[index]; !ok {
		s.order = append(s.order, index)
	}
	s.cache[index] = h
	s.head = h
	limit := s.CacheLimit
	if limit < 1000 {
		limit = 1000
	}
	for len(s.order) > limit {
		delete(s.cache, s.order[0])
		s.order = s.order[1:]
	}
}
func (s *Source) Read(index uint64) (*types.Header, error) {
	if h := s.cache[index]; h != nil {
		return h, nil
	}
	if s.Blocks != "" {
		raw, err := os.ReadFile(filepath.Join(s.Blocks, fmt.Sprintf("%012d.rlp", index)))
		if err != nil {
			return nil, err
		}
		b, err := codec.DecodeBlock(raw)
		if err != nil {
			return nil, err
		}
		if b.Header.Number.Big().Uint64() != index {
			return nil, fmt.Errorf("block index %d differs from full number %s", index, b.Header.Number)
		}
		s.remember(index, b.Header)
		return b.Header, nil
	}
	if err := s.Prefetch(index, index); err != nil {
		return nil, err
	}
	return s.cache[index], nil
}
func (s *Source) Prefetch(from, to uint64) error {
	if to < from || to-from >= 100 {
		return fmt.Errorf("header batch must contain 1..100 indices")
	}
	if s.RPC == nil {
		for n := from; ; n++ {
			if _, err := s.Read(n); err != nil {
				return err
			}
			if n == to {
				break
			}
		}
		return nil
	}
	requests := make([]rpc.Request, 0, int(to-from)+1)
	for n := from; ; n++ {
		requests = append(requests, rpc.Request{Method: "eth_getBlockByNumber", Params: []any{"0x" + strconv.FormatUint(n, 16), false}})
		if n == to {
			break
		}
	}
	answers, err := s.RPC.Batch(s.Context, requests)
	if err != nil {
		return err
	}
	for i, a := range answers {
		if a.Error != nil {
			return a.Error
		}
		h, err := DecodeJSON(a.Result)
		if err != nil {
			return fmt.Errorf("header %d: %w", from+uint64(i), err)
		}
		n := from + uint64(i)
		if h.Number.Big().Uint64() != n {
			return fmt.Errorf("RPC index %d differs from full number %s", n, h.Number)
		}
		s.remember(n, h)
	}
	return nil
}
func (s *Source) HeaderByNumber(n uint64) *types.Header {
	h, err := s.Read(n)
	if err != nil {
		s.Err = err
	}
	return h
}
func (s *Source) Header(hash types.Hash, n uint64) *types.Header {
	h := s.HeaderByNumber(n)
	if h == nil {
		return nil
	}
	if codec.BlockHash(h) != hash {
		s.Err = fmt.Errorf("parent hash conflict at %d", n)
		return nil
	}
	return h
}
func (s *Source) Head() *types.Header { return s.head }
func (s *Source) HeaderByHash(hash types.Hash) *types.Header {
	for _, h := range s.cache {
		if codec.BlockHash(h) == hash {
			return h
		}
	}
	if s.RPC == nil {
		return nil
	}
	return s.byHash(hash)
}
func (s *Source) byHash(hash types.Hash) *types.Header {
	a, err := s.RPC.Batch(s.Context, []rpc.Request{{Method: "eth_getBlockByHash", Params: []any{hash.Hex(), false}}})
	if err == nil && a[0].Error != nil {
		err = a[0].Error
	}
	var h *types.Header
	if err == nil {
		h, err = DecodeJSON(a[0].Result)
	}
	if err != nil {
		s.Err = err
		return nil
	}
	if codec.BlockHash(h) != hash {
		s.Err = fmt.Errorf("RPC hash conflict")
		return nil
	}
	s.remember(h.Number.Big().Uint64(), h)
	return h
}
func (s *Source) HasBlock(hash types.Hash, n uint64) bool { return s.Header(hash, n) != nil }
