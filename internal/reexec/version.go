package reexec

import (
	_ "embed"
	"encoding/json"
)

// The exact module origin binds the current dependency to a full commit.
// No short-prefix inference or network lookup is performed during a run.
//
//go:embed core-pin.json
var corePinJSON []byte

func canonicalVersion(v string) string {
	var pin struct{ Version, Commit, Sum string }
	if json.Unmarshal(corePinJSON, &pin) == nil && v == pin.Version {
		return pin.Commit
	}
	return v
}
func sameVersion(a, b string) bool {
	return a != "unknown" && b != "unknown" && canonicalVersion(a) == canonicalVersion(b)
}

// LinkedCommit resolves the runtime module version only through the exact
// embedded origin pin. Unknown or locally replaced builds stay unavailable.
func LinkedCommit() string {
	v := LinkedVersion()
	commit := canonicalVersion(v)
	if len(commit) != 40 {
		return "unknown"
	}
	return commit
}
