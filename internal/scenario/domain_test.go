package scenario

import (
	"errors"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"testing"
)

// A detached metadata row cannot grant the legacy model a signing domain.
func TestRecordedDomainMessageRequiresExplicitModel(t *testing.T) {
	row := messages.Record{SigningProfile: &messages.SigningProfile{Version: "1", Activation: "3", SHA256: "declaration"}}
	_, err := BindRecordedMessage(RecordedMessageSelection{}, row, nil, 0, nil)
	if !errors.Is(err, ErrRecordedDomainModelUnavailable) {
		t.Fatal("selected context entered legacy model", err)
	}
}
