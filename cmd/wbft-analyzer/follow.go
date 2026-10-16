package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/ingest"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft-analyzer/internal/source/rpc"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/0xmhha/wbft/types"
)

type followList []string

func (f *followList) String() string     { return "" }
func (f *followList) Set(v string) error { *f = append(*f, v); return nil }

func runFollow(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("follow", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsn := fs.String("db", os.Getenv("WBFT_ANALYZER_DB"), "PostgreSQL DSN")
	name := fs.String("name", "", "follow session name")
	config := fs.String("config", "", "genesis or chain configuration JSON")
	from := fs.String("from", "", "first non-genesis canonical index, decimal; reused on restart")
	network := fs.String("network", "", "network display name")
	poll := fs.Duration("poll", 5*time.Second, "retry/poll interval, at least 100ms")
	duration := fs.Duration("duration", 0, "optional run duration; default: until interrupted")
	rate := fs.Float64("rate", 5, "RPC batches/second per source, at most 5")
	var urls, nodes followList
	fs.Var(&urls, "rpc", "native read-only endpoint (repeatable; never persisted)")
	fs.Var(&nodes, "node", "stable source label (repeat in endpoint order)")
	e := fs.Parse(args)
	if e == flag.ErrHelp {
		return exitOK
	}
	if e != nil {
		return exitUsage
	}
	start, e := strconv.ParseUint(*from, 10, 64)
	if e != nil || start == 0 || start == ^uint64(0) || *dsn == "" || *config == "" || !logs.Identifier(*name) || len(*name) > 80 || len(urls) == 0 || len(urls) > 16 || len(nodes) != 0 && len(nodes) != len(urls) || *poll < 100*time.Millisecond || *duration < 0 || fs.NArg() != 0 {
		fs.Usage()
		return exitUsage
	}
	if len(nodes) == 0 {
		for i := range urls {
			nodes = append(nodes, fmt.Sprintf("rpc-%d", i+1))
		}
	}
	seen := map[string]bool{}
	clients := make([]*rpc.Client, len(urls))
	for i, url := range urls {
		if !logs.Identifier(nodes[i]) || len(nodes[i]) > 32 || seen[nodes[i]] {
			fs.Usage()
			return exitUsage
		}
		seen[nodes[i]] = true
		clients[i], e = rpc.New(url, *rate)
		if e != nil {
			fmt.Fprintln(stderr, e)
			return exitUsage
		}
	}
	raw, e := os.ReadFile(*config)
	if e != nil {
		fmt.Fprintln(stderr, "follow configuration could not be read")
		return exitDataErr
	}
	var genesis struct{ Config json.RawMessage }
	if json.Unmarshal(raw, &genesis) == nil && len(genesis.Config) > 0 {
		raw = genesis.Config
	}
	if cfg, err := types.ParseChainConfig(raw); err != nil || cfg.ChainID == nil {
		fmt.Fprintln(stderr, "follow configuration is invalid")
		return exitDataErr
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *duration > 0 {
		var stop context.CancelFunc
		ctx, stop = context.WithTimeout(ctx, *duration)
		defer stop()
	}
	s, e := store.Open(ctx, *dsn)
	if e != nil {
		fmt.Fprintln(stderr, "follow database unavailable")
		return exitUnavailable
	}
	defer s.Close()
	if _, e = s.Migrate(ctx); e != nil {
		fmt.Fprintln(stderr, "follow migration failed")
		return exitInternal
	}
	type update struct {
		node   string
		result ingest.FollowResult
		err    error
		fatal  bool
	}
	updates := make(chan update, len(urls))
	var wg sync.WaitGroup
	for i := range urls {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var f *ingest.Follower
			defer func() {
				if f != nil {
					f.Close()
				}
			}()
			for ctx.Err() == nil {
				var r ingest.FollowResult
				var e error
				if f == nil {
					f, e = ingest.OpenFollower(ctx, s, ingest.FollowOptions{Name: *name + "." + nodes[i], Node: nodes[i], NetworkName: *network, From: start, Config: raw, RPC: clients[i]})
				}
				if e == nil {
					r, e = f.Step(ctx)
				}
				fatal := errors.Is(e, ingest.ErrFollowIdentity) || errors.Is(e, store.ErrFollowCursor)
				if e != nil && f != nil && ctx.Err() == nil {
					issue := "collection_retry"
					if errors.Is(e, ingest.ErrFollowIncomplete) {
						issue = "participation_incomplete"
					}
					if errors.Is(e, ingest.ErrFollowIdentity) {
						issue = "identity_conflict"
					}
					if errors.Is(e, store.ErrFollowCursor) {
						issue = "stored_cursor_conflict"
					}
					_ = s.FollowIssue(ctx, f.Dataset.ID, issue)
				}
				select {
				case updates <- update{nodes[i], r, e, fatal}:
				case <-ctx.Done():
					return
				}
				if fatal {
					return
				}
				if e == nil && r.Headers > 0 {
					continue
				}
				timer := time.NewTimer(*poll)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					return
				}
			}
		}(i)
	}
	go func() { wg.Wait(); close(updates) }()
	code := exitOK
	for u := range updates {
		if u.err != nil {
			if ctx.Err() != nil {
				continue
			}
			// Transport errors can contain credentials; log labels and categories only.
			detail := "source unavailable or incomplete; cursor retained"
			if errors.Is(u.err, ingest.ErrFollowIncomplete) {
				detail = "participation gap or changing summary; cursor retained"
			}
			if u.fatal {
				detail = "source identity or stored cursor conflict; stopped"
				code = exitDataErr
			}
			diagnostic := ingest.FollowFailure(u.err)
			if diagnostic.Stage != "" {
				detail += fmt.Sprintf(" (stage=%s kind=%s", diagnostic.Stage, diagnostic.Kind)
				if diagnostic.Code != "" {
					detail += " code=" + diagnostic.Code
				}
				detail += ")"
			}
			fmt.Fprintf(stderr, "follow %s: %s\n", u.node, detail)
		} else if u.result.Headers > 0 {
			if e = json.NewEncoder(stdout).Encode(struct {
				Node string `json:"node"`
				ingest.FollowResult
			}{u.node, u.result}); e != nil {
				cancel()
				code = exitInternal
			}
		}
	}
	return code
}
