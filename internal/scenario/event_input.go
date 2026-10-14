package scenario

import (
	"context"
	"errors"
	"io"

	"github.com/0xmhha/wbft-analyzer/internal/source/events"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
)

type EventInput struct {
	Source  Input        `json:"source"`
	Stats   logs.Stats   `json:"stats"`
	Records []logs.Event `json:"-"`
}

// InspectEvents hashes and schema-checks the exact supplied immutable stream.
// Neither mutable stored projections nor a caller's completeness flag are
// accepted as a replacement for the original input bytes.
func InspectEvents(ctx context.Context, source Input, reader io.Reader) (EventInput, error) {
	out := EventInput{Source: source, Records: []logs.Event{}}
	if source.Kind != "events" || !logs.Identifier(source.ID) || source.Node == "" || !hexLength(source.SHA256, 64) {
		return out, errors.New("invalid scenario event identity")
	}
	limited := &io.LimitedReader{R: reader, N: (1 << 30) + 1}
	stats, err := events.Read(ctx, limited, source.Node, source.ID, func(x logs.Event) error {
		if len(out.Records) >= 1000000 {
			return errors.New("scenario event count exceeds bound")
		}
		out.Records = append(out.Records, x)
		return nil
	})
	out.Stats = stats
	if err != nil {
		return out, err
	}
	if limited.N <= 0 || stats.SHA256 != source.SHA256 {
		return out, errors.New("scenario event bytes changed or exceed bound")
	}
	if stats.Malformed > 0 || stats.SequenceGaps > 0 {
		return out, errors.New("scenario event stream incomplete")
	}
	// Stamp order across asynchronous observers is diagnostic. It neither
	// proves host-clock failure nor licenses correcting any timestamp. Each
	// fitted lifecycle and timing pair must validate its own recorded clocks.
	if len(out.Records) == 0 {
		return out, errors.New("scenario events unavailable")
	}
	return out, nil
}
