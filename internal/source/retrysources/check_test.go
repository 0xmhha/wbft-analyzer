package retrysources

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/0xmhha/wbft/observe/journal"
)

func testLimits(t *testing.T) journal.RetrySourceLimits {
	t.Helper()
	raw := []byte(`{"Timers":{"Core":{"Records":1000,"Runs":4,"Steps":1000,"Environments":4000,"Outputs":4000,"Bytes":67108864},"Operations":4000,"Bindings":4000,"Bytes":67108864},"Signer":{"Lifetimes":16,"Operations":4000,"Records":4000,"Bytes":67108864},"Writes":{"Records":1000,"Ledgers":16,"Reordered":64}}`)
	limits, err := Limits(raw)
	if err != nil {
		t.Fatal(err)
	}
	return limits
}
func TestLimitsRejectsUnknownDuplicateAndMissingBounds(t *testing.T) {
	_ = testLimits(t)
	for _, raw := range []string{`null`, `{}`, `{"Timers":{},"Timers":{}}`, `{"extra":1}`, `{} {}`} {
		if _, err := Limits([]byte(raw)); err == nil {
			t.Fatal("invalid inspection limits accepted")
		}
	}
}
func TestOriginalProfileSourceMatchesCoreAndRemainsUnavailableWithoutOwner(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "retry"}[enabled], func(t *testing.T) {
			dir := t.TempDir()
			identity := journal.Identity{Run: "normal-retry-source"}
			if enabled {
				identity.Core.RoundChangeRetry = &journal.RoundChangeRetryOptions{Profile: journal.RoundChangeRetryProfile, MaxIntervalMs: 8000}
			}
			writer, err := journal.Open(journal.Options{Dir: dir, Synchronous: true}, identity)
			if err != nil {
				t.Fatal(err)
			}
			if err = writer.Close(); err != nil {
				t.Fatal(err)
			}
			limits := testLimits(t)
			got, err := Check(t.Context(), dir, limits)
			if err != nil {
				t.Fatal(err)
			}
			records, err := journal.ReadAll(nil, dir)
			if err != nil {
				t.Fatal(err)
			}
			want, err := journal.CheckRoundChangeRetrySources(records, limits)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) || got.Status != "unavailable" || got.PhysicalStatus != "unavailable" {
				t.Fatal("partial source became proof", got, want)
			}
			if enabled {
				segment := records[0].Body.(*journal.SegmentRec)
				if segment.Core.RoundChangeRetry == nil || segment.Core.RoundChangeRetry.MaxIntervalMs != 8000 {
					t.Fatal("original profile precision lost")
				}
			}
			encoded, err := json.Marshal(got)
			if err != nil || len(encoded) == 0 {
				t.Fatal(err)
			}
		})
	}
}
