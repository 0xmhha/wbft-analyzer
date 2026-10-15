package scenario

import (
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"path/filepath"
)

// SourceSnapshot is private storage metadata. It is never an API response.
// Each event stream retains its exact complete-line prefix in ordered objects.
type SourceSnapshot struct {
	Transport *TransportSnapshot    `json:"transport,omitempty"`
	Runtime   []RuntimeObject       `json:"runtime,omitempty"`
	Chain     messages.ArchivedFile `json:"chain"`
	Events    []EventObject         `json:"events"`
}
type RuntimeObject struct {
	Source Input                 `json:"source"`
	File   messages.ArchivedFile `json:"file"`
}
type EventObject struct {
	Source Input                   `json:"source"`
	Files  []messages.ArchivedFile `json:"files"`
}

func (s SourceSnapshot) Objects() []messages.ArchivedFile {
	out := []messages.ArchivedFile{s.Chain}
	if s.Transport != nil {
		out = append(out, s.Transport.Objects()...)
	}
	for _, e := range s.Events {
		out = append(out, e.Files...)
	}
	for _, r := range s.Runtime {
		out = append(out, r.File)
	}
	return out
}
func (s SourceSnapshot) Rebase(directory string) SourceSnapshot {
	out := s
	if s.Transport != nil {
		rebased := s.Transport.Rebase(directory)
		out.Transport = &rebased
	}
	out.Runtime = append([]RuntimeObject(nil), s.Runtime...)
	for i := range out.Runtime {
		out.Runtime[i].File.Path = filepath.Join(directory, out.Runtime[i].File.SHA256)
	}
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

// TransportSnapshot retains the declaration and every original witness object.
type EvidenceObject struct {
	Source Input                 `json:"source"`
	File   messages.ArchivedFile `json:"file"`
}
type TransportWindowObject struct {
	Input       string         `json:"input"`
	Certificate EvidenceObject `json:"certificate"`
}
type TransportSnapshot struct {
	Declaration EvidenceObject          `json:"declaration"`
	Controller  EvidenceObject          `json:"controller"`
	Headers     []EvidenceObject        `json:"headers"`
	Windows     []TransportWindowObject `json:"windows"`
}

func (s TransportSnapshot) Objects() []messages.ArchivedFile {
	out := []messages.ArchivedFile{s.Declaration.File, s.Controller.File}
	for _, h := range s.Headers {
		out = append(out, h.File)
	}
	for _, w := range s.Windows {
		out = append(out, w.Certificate.File)
	}
	return out
}
func (s TransportSnapshot) Rebase(directory string) TransportSnapshot {
	out := s
	out.Declaration.File.Path = filepath.Join(directory, s.Declaration.File.SHA256)
	out.Controller.File.Path = filepath.Join(directory, s.Controller.File.SHA256)
	out.Headers = append([]EvidenceObject(nil), s.Headers...)
	for i := range out.Headers {
		out.Headers[i].File.Path = filepath.Join(directory, out.Headers[i].File.SHA256)
	}
	out.Windows = append([]TransportWindowObject(nil), s.Windows...)
	for i := range out.Windows {
		out.Windows[i].Certificate.File.Path = filepath.Join(directory, out.Windows[i].Certificate.File.SHA256)
	}
	return out
}
