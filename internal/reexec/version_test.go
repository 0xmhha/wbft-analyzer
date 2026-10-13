package reexec

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestCorePinTracksExactModuleAndChecksum(t *testing.T) {
	var pin struct{ Version, Commit, Sum string }
	if err := json.Unmarshal(corePinJSON, &pin); err != nil {
		t.Fatal(err)
	}
	mod, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	sum, err := os.ReadFile("../../go.sum")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mod), "github.com/0xmhha/wbft "+pin.Version) || !strings.Contains(string(sum), "github.com/0xmhha/wbft "+pin.Version+" "+pin.Sum+"\n") || len(pin.Commit) != 40 || !strings.HasSuffix(pin.Version, pin.Commit[:12]) {
		t.Fatal("core identity pin does not match dependency")
	}
	if !sameVersion(pin.Version, pin.Commit) || sameVersion("unknown", "unknown") || sameVersion(pin.Commit, pin.Commit+"-modified") || sameVersion(pin.Commit, "v0.0.0-20000101000000-"+pin.Commit[:12]) {
		t.Fatal("unsafe version alias")
	}
}
