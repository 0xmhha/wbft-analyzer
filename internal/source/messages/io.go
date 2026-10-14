package messages

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/0xmhha/wbft/observe/journal"
)

// IOInterval retains the original measured endpoints with lossless nanoseconds.
// It is absent when not measured; the callback clock is a separate observation.
type IOInterval struct {
	StartWall string `json:"start_wall"`
	EndWall   string `json:"end_wall"`
	StartMono string `json:"start_mono_ns"`
	EndMono   string `json:"end_mono_ns"`
}

func journalIOInterval(x *journal.IOInterval) *IOInterval {
	if x == nil {
		return nil
	}
	return &IOInterval{StartWall: time.Unix(0, x.StartWallNs).UTC().Format(time.RFC3339Nano), EndWall: time.Unix(0, x.EndWallNs).UTC().Format(time.RFC3339Nano), StartMono: strconv.FormatInt(int64(x.StartMono), 10), EndMono: strconv.FormatInt(int64(x.EndMono), 10)}
}

func frameIOInterval(x frameRecord, write string) (*IOInterval, error) {
	if len(x.IO) == 0 {
		return nil, nil
	}
	fail := func() (*IOInterval, error) { return nil, errors.New("invalid frame I/O evidence") }
	if x.Type != "frame" || x.Mono == nil || write == "not_attached" || !uniqueObject(x.IO) {
		return fail()
	}
	var raw struct {
		StartWall string `json:"start_wall"`
		EndWall   string `json:"end_wall"`
		StartMono *int64 `json:"start_mono_ns"`
		EndMono   *int64 `json:"end_mono_ns"`
	}
	d := json.NewDecoder(bytes.NewReader(x.IO))
	d.DisallowUnknownFields()
	if d.Decode(&raw) != nil || raw.StartMono == nil || raw.EndMono == nil || *raw.StartMono < 0 || *raw.EndMono < *raw.StartMono || *raw.EndMono > *x.Mono {
		return fail()
	}
	start, err := time.Parse(time.RFC3339Nano, raw.StartWall)
	if err != nil {
		return fail()
	}
	end, err := time.Parse(time.RFC3339Nano, raw.EndWall)
	if err != nil {
		return fail()
	}
	return &IOInterval{StartWall: start.UTC().Format(time.RFC3339Nano), EndWall: end.UTC().Format(time.RFC3339Nano), StartMono: strconv.FormatInt(*raw.StartMono, 10), EndMono: strconv.FormatInt(*raw.EndMono, 10)}, nil
}
