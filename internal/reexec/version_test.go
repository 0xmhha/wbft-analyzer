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
	for _, historical := range []struct{ module, commit string }{
		{"v0.0.0-20261020013130-753480424f31", "753480424f3164270d3d70c91787bee032a2088a"},
		{"v0.0.0-20261019193246-df1dcdbf777f", "df1dcdbf777fa28c411a25c396f94f0443ff04da"},
		{"v0.0.0-20261019162901-72c353d135de", "72c353d135de57c36c65a2733a0a136ff831b649"},
		{"v0.0.0-20261019124713-186324c8ace2", "186324c8ace2e895928af467b6269a03c0d62333"},
		{"v0.0.0-20261019091709-3480894b068a", "3480894b068a0694bf55f7a3199af7267b89e3a3"},
		{"v0.0.0-20261017021619-54c2a5417d23", "54c2a5417d230daefd8ef49e696ff8af35d66c0d"},
		{"v0.0.0-20261019010544-fdaa84fde060", "fdaa84fde06014b462122e4c7b53cc7f5a311bd6"},
		{"v0.0.0-20261019032743-5c5a453e6f5a", "5c5a453e6f5a313f61bc9c1db680d5a2943a8be0"},
		{"v0.0.0-20261019062449-5c5a8f740621", "5c5a8f7406212996efc98a4c194afe8deeb6d5cc"},
	} {
		if sameVersion(historical.module, pin.Commit) || sameVersion(historical.commit, pin.Version) {
			t.Fatal("historical source was relabeled as the current core")
		}
	}
	if !sameVersion(pin.Version, pin.Commit) || sameVersion("unknown", "unknown") || sameVersion(pin.Commit, pin.Commit+"-modified") || sameVersion(pin.Commit, "v0.0.0-20000101000000-"+pin.Commit[:12]) {
		t.Fatal("unsafe version alias")
	}
}
