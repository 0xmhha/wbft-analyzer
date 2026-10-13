package logs

import (
	"strings"
	"testing"
)

func TestLegacyDeclarationsRequireExactInputSnapshots(t *testing.T) {
	ds := []LegacyAssociation{{Address: "0x" + strings.Repeat("1", 40), Input: "legacy", SHA256: strings.Repeat("a", 64), NativeInput: "native", NativeSHA256: strings.Repeat("b", 64), From: "2020-01-01T00:00:00Z", To: "2020-01-01T00:00:10Z"}}
	in := []PreparedInput{{Summary: InputSummary{ID: "legacy", Kind: "log", Profile: "gstable@740526d03", SHA256: strings.Repeat("a", 64)}}, {Summary: InputSummary{ID: "native", Kind: "events", SHA256: strings.Repeat("b", 64)}}}
	if e := validateLegacyAssociations(ds, in); e != nil {
		t.Fatal(e)
	}
	for _, change := range []string{"hash", "kind", "duplicate", "window", "address"} {
		t.Run(change, func(t *testing.T) {
			copyD := append([]LegacyAssociation(nil), ds...)
			copyI := append([]PreparedInput(nil), in...)
			switch change {
			case "hash":
				copyD[0].SHA256 = strings.Repeat("c", 64)
			case "kind":
				copyI[1].Summary.Kind = "log"
			case "duplicate":
				copyD = append(copyD, copyD[0])
			case "window":
				copyD[0].To = "2020-01-03T00:00:00Z"
			case "address":
				copyD[0].Address = "label"
			}
			if validateLegacyAssociations(copyD, copyI) == nil {
				t.Fatal("unsupported declaration accepted")
			}
		})
	}
}
