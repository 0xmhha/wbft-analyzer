package governance

import (
	"encoding/json"
	"testing"
)

func TestNoKeyPresenceDoesNotTurnNullOrMissingIntoEmptyClaim(t *testing.T) {
	for _, test := range []struct {
		extra    string
		reported bool
	}{{"", false}, {`,"NoKey":null`, false}, {`,"NoKey":[]`, true}} {
		raw := json.RawMessage(`[{"number":"0xa","ops":[],"epoch":{"Candidates":[],"Validators":[],"Added":[],"Removed":[]` + test.extra + `}}]`)
		rows, err := changes(raw, 10, 10)
		if err != nil || len(rows) != 1 || rows[0].Epoch == nil || rows[0].Epoch.NoKeyReported != test.reported {
			t.Fatal(test, rows, err)
		}
	}
}
