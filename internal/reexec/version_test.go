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
		{"v0.0.0-20261024072729-5129d2bbf8ac", "5129d2bbf8ac53d62205ea2559bd137f207c0863"},
		{"v0.0.0-20261024052525-63f309906fba", "63f309906fba13264171d867f1860805247248e2"},
		{"v0.0.0-20261024030958-cace8f027c8c", "cace8f027c8c952ec06b6247cb09b91fa187b2e7"},
		{"v0.0.0-20261024010510-6f5036b7d4ef", "6f5036b7d4ef44319f6dfd8d8a5b583ee8312e88"},
		{"v0.0.0-20261023230918-edaa957ee067", "edaa957ee0674f458ea45b487b8cdbb748c23977"},
		{"v0.0.0-20261023204648-30de21926108", "30de219261082bb274525181ff365073c7b79360"},
		{"v0.0.0-20261023193349-50d38c29bcc3", "50d38c29bcc36ee8207cf2a28054c3272d5f2257"},
		{"v0.0.0-20261023180431-1c8fafe52521", "1c8fafe52521344ee648e4e390ef67bbfa594e9a"},
		{"v0.0.0-20261023060044-0c0299b512d3", "0c0299b512d3900a9de8097e17030f771b86ba94"},
		{"v0.0.0-20261023035041-b6397ac1e31a", "b6397ac1e31a32c5c285c89bf25a31c232a0afba"},
		{"v0.0.0-20261021101214-85897dc55fb2", "85897dc55fb26824a59d0f9292b1e29f7e2e698f"},
		{"v0.0.0-20261021025603-5279cbb8ace1", "5279cbb8ace107787c876eb626d7bfbc044e1730"},
		{"v0.0.0-20261021003322-f0aa974a27f7", "f0aa974a27f7545f7ae9347b8b3962d2b3ddcf76"},
		{"v0.0.0-20261020224440-878148416971", "8781484169717022da38312808a98c0e9161a517"},
		{"v0.0.0-20261020210040-4bf2de4743e8", "4bf2de4743e8dddb464dd40b96358e5f5f8ba589"},
		{"v0.0.0-20261020192618-3ce118ba079a", "3ce118ba079adc662523914bd992a667eed217fc"},
		{"v0.0.0-20261020173747-567dcb7467b4", "567dcb7467b4e139fcd9f146478bdc199e678f2d"},
		{"v0.0.0-20261020153004-0c2c9eb11747", "0c2c9eb1174784f8ad2a2caaa2a3ac317b3f9a77"},
		{"v0.0.0-20261020133747-7c0554b59388", "7c0554b59388c3c061c72a021e9a75a82f9a728f"},
		{"v0.0.0-20261020105830-e47f130ad380", "e47f130ad3809748d230b068f66f5e9cc6998bcc"},
		{"v0.0.0-20261020074113-cab045d41338", "cab045d413382fa60d3158f1a37571aac5db6fcf"},
		{"v0.0.0-20261020043318-7c6797ada0a5", "7c6797ada0a50010775c14122998e329436ec552"},
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
