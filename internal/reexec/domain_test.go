package reexec

import (
	"errors"
	"github.com/0xmhha/wbft-analyzer/internal/source/domainprofile"
	"github.com/0xmhha/wbft/observe/journal"
	"testing"
)

func TestDomainProfileErrorClasses(t *testing.T) {
	for _, err := range []error{domainprofile.ErrUnsupported, journal.ErrSignerSourceUnsupported, journal.ErrDomainSourceUnsupported} {
		if answerErrorCode(err) != "unsupported_profile" || sourceIssue(err) != "unsupported_profile" {
			t.Fatal("unsupported source became replay mismatch", err)
		}
	}
	if sourceIssue(domainprofile.ErrInvalid) != "inconsistent_source_profile" || sourceIssue(journal.ErrRecord) != "damaged_journal" || answerErrorCode(errors.New("I/O")) == "unsupported_profile" {
		t.Fatal("supported invalid or I/O was mislabeled")
	}
}
