// Package domainprofile binds public source declarations to their recorded
// chain identity. A validated declaration is not independent authentication.
package domainprofile

import (
	"crypto/sha256"
	"errors"

	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

var ErrUnsupported = errors.New("unsupported source domain profile")
var ErrInvalid = errors.New("inconsistent source domain declaration")

func Unsupported(err error) bool {
	return errors.Is(err, ErrUnsupported) || errors.Is(err, journal.ErrDomainSourceUnsupported) || errors.Is(err, journal.ErrSignerSourceUnsupported) || errors.Is(err, types.ErrRoundChangeDomainVersion)
}

func Segment(segment *journal.SegmentRec) (*types.RoundChangeDomain, error) {
	if err := segment.ValidateDomainIdentity(); err != nil {
		if Unsupported(err) || len(segment.Core.DomainBytes) == 0 && errors.Is(err, types.ErrRoundChangeDomain) {
			return nil, ErrUnsupported
		}
		return nil, ErrInvalid
	}
	if len(segment.Core.DomainBytes) == 0 {
		return nil, nil
	}
	config, err := segment.Core.Configuration()
	if err != nil {
		return nil, ErrInvalid
	}
	domain, err := segment.Core.DomainOptions(config)
	if Unsupported(err) {
		return nil, ErrUnsupported
	}
	if err != nil {
		return nil, ErrInvalid
	}
	return domain, nil
}

func Record(record journal.Record) error {
	if segment, ok := record.Body.(*journal.SegmentRec); ok {
		_, err := Segment(segment)
		return err
	}
	return nil
}

type owner struct {
	hash     [32]byte
	selected bool
}

// Registry bounds retained writer names and declaration hashes. Legacy-only
// overflow drops the optional index and preserves streaming; a later selected
// profile then has insufficient provenance. These are logical span/count
// limits, not bounds on decoder allocation, process heap, or verification CPU.
type Registry struct {
	owners              map[string]owner
	bytes               uint64
	selected, exhausted bool
}

func (r *Registry) Observe(segment *journal.SegmentRec) (*types.RoundChangeDomain, error) {
	return r.observe(segment, 100000, 16<<20)
}

func (r *Registry) observe(segment *journal.SegmentRec, maxOwners int, maxBytes uint64) (*types.RoundChangeDomain, error) {
	domain, err := Segment(segment)
	if err != nil {
		return nil, err
	}
	selected := domain != nil
	if r.exhausted {
		if selected {
			return nil, ErrUnsupported
		}
		return nil, nil
	}
	if r.owners == nil {
		r.owners = map[string]owner{}
	}
	hash := sha256.Sum256(segment.Core.DomainBytes)
	if previous, ok := r.owners[segment.Run]; ok {
		if previous.hash != hash && (selected || previous.selected) {
			return nil, ErrInvalid
		}
		return domain, nil
	}
	span := uint64(len(segment.Run)) + 33
	if len(r.owners) >= maxOwners || span > maxBytes || r.bytes > maxBytes-span {
		if selected || r.selected {
			return nil, ErrUnsupported
		}
		r.owners = nil
		r.bytes = 0
		r.exhausted = true
		return nil, nil
	}
	r.owners[segment.Run] = owner{hash, selected}
	r.bytes += span
	r.selected = r.selected || selected
	return domain, nil
}
