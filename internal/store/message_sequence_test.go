package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
)

func TestMessageSourceWithoutSequenceKeepsAbsenceAndLegacyConstraints(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	d, release, err := s.BeginMessages(ctx, NetworkKey{ChainID: "9", GenesisHash: "0x" + strings.Repeat("0", 64)}, "optional-source-sequence", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := s.PutMessageInput(ctx, d.ID, messages.Summary{ID: "typed", Kind: "sync_notifications", Node: "node"}); err != nil {
		t.Fatal(err)
	}
	header := messages.Record{Input: "typed", File: "notifications.jsonl", Ordinal: 1, Node: "node", Run: "controlled", Type: "sync_notification_source"}
	notification := header
	notification.Ordinal = 2
	notification.Type = "sync_notification"
	notification.Seq = "18446744073709551615"
	footer := header
	footer.Ordinal = 3
	if err := s.PutMessageRecords(ctx, d.ID, []messages.Record{header, notification, footer}, 3); err != nil {
		t.Fatal(err)
	}
	for _, ordinal := range []int64{1, 3} {
		r, err := s.MessageRecordAt(ctx, d.ID, "typed", "notifications.jsonl", ordinal)
		if err != nil || r.Seq != "" {
			t.Fatal("source record gained an invented sequence", r, err)
		}
	}
	r, err := s.MessageRecordAt(ctx, d.ID, "typed", "notifications.jsonl", 2)
	if err != nil || r.Seq != notification.Seq {
		t.Fatal("exact notification sequence changed", r, err)
	}
	var absent int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM message_records WHERE dataset_id=$1 AND seq IS NULL`, d.ID).Scan(&absent); err != nil || absent != 2 {
		t.Fatal(absent, err)
	}
	legacy := header
	legacy.Ordinal = 4
	legacy.Type = "frame"
	if err := s.PutMessageRecords(ctx, d.ID, []messages.Record{legacy}, 4); err == nil {
		t.Fatal("legacy frame accepted a missing source sequence")
	}
	missingNotification := header
	missingNotification.Ordinal = 4
	missingNotification.Type = "sync_notification"
	if err := s.PutMessageRecords(ctx, d.ID, []messages.Record{missingNotification}, 4); err == nil {
		t.Fatal("notification accepted a missing source sequence")
	}
	duplicate := notification
	duplicate.Ordinal = 4
	if err := s.PutMessageRecords(ctx, d.ID, []messages.Record{duplicate}, 4); err == nil {
		t.Fatal("notification sequence uniqueness was weakened")
	}
	var count int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM message_records WHERE dataset_id=$1`, d.ID).Scan(&count); err != nil || count != 3 {
		t.Fatal("refused rows leaked through their transactions", count, err)
	}
}
