package scenario

import (
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"path/filepath"
)

// SourceSnapshot is private storage metadata. It is never an API response.
// Each event stream retains its exact complete-line prefix in ordered objects.
type SourceSnapshot struct {
	Chain  messages.ArchivedFile `json:"chain"`
	Events []EventObject         `json:"events"`
}
type EventObject struct {
	Source Input                   `json:"source"`
	Files  []messages.ArchivedFile `json:"files"`
}

func (s SourceSnapshot) Objects() []messages.ArchivedFile {
	out := []messages.ArchivedFile{s.Chain}
	for _, e := range s.Events {
		out = append(out, e.Files...)
	}
	return out
}
func (s SourceSnapshot) Rebase(directory string) SourceSnapshot {
	out := s
	out.Chain.Path = filepath.Join(directory, s.Chain.SHA256)
	out.Events = make([]EventObject, len(s.Events))
	for i, e := range s.Events {
		out.Events[i] = e
		out.Events[i].Files = append([]messages.ArchivedFile(nil), e.Files...)
		for j, f := range e.Files {
			out.Events[i].Files[j].Path = filepath.Join(directory, f.SHA256)
		}
	}
	return out
}
