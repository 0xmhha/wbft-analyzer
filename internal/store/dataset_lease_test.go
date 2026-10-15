package store

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// delayedTerminateConn emulates a server that has not processed disconnect
// yet. SQL and replies pass unchanged; only termination waits for the gate.
type delayedTerminateConn struct {
	net.Conn
	resume   <-chan struct{}
	deferred atomic.Bool
	once     sync.Once
	closed   *sync.WaitGroup
	delayed  *atomic.Int32
}

func (c *delayedTerminateConn) Write(p []byte) (int, error) {
	if bytes.Equal(p, []byte{'X', 0, 0, 0, 4}) {
		c.deferred.Store(true)
		c.delayed.Add(1)
		return len(p), nil
	}
	return c.Conn.Write(p)
}
func (c *delayedTerminateConn) Close() error {
	if !c.deferred.Load() {
		return c.Conn.Close()
	}
	c.once.Do(func() {
		c.closed.Add(1)
		go func() {
			defer c.closed.Done()
			<-c.resume
			_, _ = c.Conn.Write([]byte{'X', 0, 0, 0, 4})
			_ = c.Conn.Close()
		}()
	})
	return nil
}

func TestDatasetLeaseUnlockDoesNotWaitForBackendDisconnect(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	dataset := jobDataset(t, s)
	resume := make(chan struct{})
	var closed sync.WaitGroup
	var delayed atomic.Int32
	cfg := s.pool.Config()
	dial := cfg.ConnConfig.DialFunc
	cfg.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &delayedTerminateConn{Conn: conn, resume: resume, closed: &closed, delayed: &delayed}, nil
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		close(resume)
		t.Fatal(err)
	}
	clone := &Store{pool: pool}
	t.Cleanup(func() { close(resume); clone.Close(); closed.Wait() })
	for _, shared := range []bool{false, true} {
		release, err := clone.datasetLease(ctx, dataset, shared, false)
		if err != nil {
			t.Fatal(err)
		}
		blocked, err := s.datasetLease(ctx, dataset, false, false)
		if err == nil {
			blocked()
			release()
			t.Fatal("active lease did not fence the next owner")
		}
		if !errors.Is(err, ErrDatasetBusy) {
			release()
			t.Fatal(err)
		}
		before := delayed.Load()
		release()
		if delayed.Load() != before+1 {
			t.Fatal("backend disconnect was not delayed")
		}
		next, err := s.datasetLease(ctx, dataset, false, false)
		if err != nil {
			t.Fatalf("released lease still held while disconnect was delayed: %v", err)
		}
		next()
	}
}

func TestDatasetLeaseReleaseAllowsImmediateExclusiveReacquisition(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	dataset := jobDataset(t, s)
	for _, shared := range []bool{false, true} {
		for i := 0; i < 32; i++ {
			release, err := s.datasetLease(ctx, dataset, shared, false)
			if err != nil {
				t.Fatal(shared, i, err)
			}
			blocked, err := s.datasetLease(ctx, dataset, false, false)
			if err == nil {
				blocked()
				release()
				t.Fatal("exclusive lease crossed an active reader or writer")
			}
			if !errors.Is(err, ErrDatasetBusy) {
				release()
				t.Fatal(err)
			}
			release()
			release()
			next, err := s.datasetLease(ctx, dataset, false, false)
			if err != nil {
				t.Fatalf("shared=%t iteration=%d: released lease still blocks the next owner: %v", shared, i, err)
			}
			next()
		}
	}
}
