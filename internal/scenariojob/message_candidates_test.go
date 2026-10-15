package scenariojob

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/scenario"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft-analyzer/internal/store"
	"github.com/jackc/pgx/v5"
)

func TestMessageCandidatesPageScannedFramesAndKeepExactCoordinates(t *testing.T) {
	dsn := os.Getenv("WBFT_ANALYZER_TEST_DSN")
	if dsn == "" {
		t.Skip("WBFT_ANALYZER_TEST_DSN is not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	token := make([]byte, 8)
	if _, err := rand.Read(token); err != nil {
		t.Fatal(err)
	}
	schema := "t_message_candidates_" + hex.EncodeToString(token)
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := conn.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Error(err)
		}
	}()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	s, err := store.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	d, release, err := s.BeginMessages(ctx, store.NetworkKey{ChainID: "7", GenesisHash: "0x" + strings.Repeat("0", 64)}, "synthetic-message-candidates", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	release()
	input := scenario.Input{ID: "wire", Kind: "frames", Node: "0x0000000000000000000000000000000000000001", SHA256: strings.Repeat("a", 64)}
	if err := s.PutMessageInput(ctx, d.ID, messages.Summary{ID: input.ID, Kind: input.Kind, Node: input.Node, SHA256: input.SHA256, Files: []messages.File{}}); err != nil {
		t.Fatal(err)
	}
	rows := []messages.Record{}
	for i := 0; i < 102; i++ {
		row := messages.Record{Input: input.ID, Node: input.Node, File: "frames-synthetic.jsonl", Ordinal: 9007199254740993 + int64(i), Seq: strconv.Itoa(i + 1), Run: "writer", Type: "frame", Dir: "out", Decode: "decoded", Signature: "recovered", PeerStatus: "recorded", Wall: "2026-01-01T00:00:01Z", Height: "3", Round: "0", Phase: "PREPARE", Peer: "0x0000000000000000000000000000000000000002", Signer: "0x0000000000000000000000000000000000000003", PayloadSHA256: strings.Repeat("b", 64)}
		if i >= 100 {
			row.Dir = "in"
		}
		rows = append(rows, row)
	}
	if err := s.PutMessageRecords(ctx, d.ID, rows, 102); err != nil {
		t.Fatal(err)
	}
	w := &Worker{store: s, sources: map[string]registered{"source": {network: d.NetworkID, duration: 2 * time.Second, request: FitRequest{Options: scenario.FitOptions{From: 3, To: 60}}, info: SourceInfo{Dataset: d.ID, Status: "complete", WallOrigin: "2026-01-01T00:00:00Z", SourceSHA: strings.Repeat("c", 64), TransportInputs: []scenario.Input{input}}}}}
	filter := store.MessageFilter{Input: input.ID}
	first, next, sha, err := w.MessageCandidates(ctx, d.NetworkID, d.ID, "source", filter)
	if err != nil || len(first) != 0 || next == nil || next.Ordinal != rows[99].Ordinal || sha != strings.Repeat("c", 64) {
		t.Fatal(first, next, err)
	}
	filter.AfterInput, filter.AfterFile, filter.AfterOrdinal = filter.Input, next.File, next.Ordinal
	second, next, _, err := w.MessageCandidates(ctx, d.NetworkID, d.ID, "source", filter)
	if err != nil || len(second) != 2 || next != nil || second[0].Ordinal != rows[100].Ordinal || second[0].InputSHA256 != input.SHA256 {
		t.Fatal(second, next, err)
	}
	raw, err := json.Marshal(second)
	if err != nil || !strings.Contains(string(raw), `"ordinal":"9007199254741093"`) {
		t.Fatal(string(raw), err)
	}
	filter.Input = "other"
	if _, _, _, err := w.MessageCandidates(ctx, d.NetworkID, d.ID, "source", filter); !errors.Is(err, ErrChange) {
		t.Fatal("unselected input accepted", err)
	}
	if _, _, _, err := w.MessageCandidates(ctx, d.NetworkID+100, d.ID, "source", filter); !errors.Is(err, ErrSource) {
		t.Fatal("cross-network source accepted", err)
	}
}
