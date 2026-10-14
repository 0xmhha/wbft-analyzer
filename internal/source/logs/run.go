package logs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/0xmhha/wbft/observe/event/schema"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const EventProfile = "wbft@events-v1"
const EventNormalizer = "wbft-event-normalization/10"

// HealthMetadataPreserved recognizes versions that retained the health fields
// needed by the missing-data view; version 6 additionally preserves null floors.
func HealthMetadataPreserved(version string) bool {
	return version == "wbft-event-normalization/5" || version == "wbft-event-normalization/6" || version == "wbft-event-normalization/7" || version == "wbft-event-normalization/8" || version == "wbft-event-normalization/9" || version == EventNormalizer
}

const ManifestFormat = "wbft-analyzer-run/1"

// NormalizerVersion changes when stored metadata interpretation changes.
const NormalizerVersion = "wbft-log-normalization/1"

type Network struct {
	ChainID     string `json:"chain_id"`
	GenesisHash string `json:"genesis_hash"`
	Name        string `json:"name"`
}
type File struct {
	Kind    string `json:"kind,omitempty"`
	ID      string `json:"id"`
	Node    string `json:"node"`
	Path    string `json:"path"`
	Profile string `json:"profile,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
}
type Manifest struct {
	LegacyAssociations []LegacyAssociation `json:"legacy_associations,omitempty"`
	Format             string              `json:"format"`
	Name               string              `json:"name"`
	Run                string              `json:"run"`
	Network            Network             `json:"network"`
	Clock              string              `json:"clock"`
	FromWall           string              `json:"from_t,omitempty"`
	ToWall             string              `json:"to_t,omitempty"`
	Inputs             []File              `json:"inputs"`
}

// InputSummary is safe import metadata. The path is local-only on PreparedInput.
type InputSummary struct {
	Kind          string `json:"kind,omitempty"`
	ID            string `json:"id"`
	Node          string `json:"node"`
	Profile       string `json:"profile"`
	ProfileSHA256 string `json:"profile_sha256"`
	SHA256        string `json:"sha256"`
	Bytes         int64  `json:"bytes"`
}
type PreparedInput struct {
	Summary InputSummary
	Path    string
	Profile *Profile
}
type Plan struct {
	Manifest Manifest
	Inputs   []PreparedInput
	Metadata json.RawMessage
	From, To time.Time
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func Identifier(s string) bool { return identifier.MatchString(s) }

func LoadManifest(path string) (Manifest, error) {
	var m Manifest
	raw, err := readSmall(path)
	if err != nil {
		return m, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil {
		return m, errors.New("invalid run manifest")
	}
	if _, err := d.Token(); err != io.EOF {
		return m, errors.New("trailing manifest data")
	}
	for i := range m.Inputs {
		if !filepath.IsAbs(m.Inputs[i].Path) {
			m.Inputs[i].Path = filepath.Join(filepath.Dir(path), m.Inputs[i].Path)
		}
		p := m.Inputs[i].Profile
		if m.Inputs[i].Kind != "events" && p != "" && p != "wbft" && p != "gstable@740526d03" && !filepath.IsAbs(p) {
			m.Inputs[i].Profile = filepath.Join(filepath.Dir(path), p)
		}
	}
	return m, nil
}

// Chainbench reads only labels and log paths from formatVersion 3. Commands,
// key paths and launch inputs are neither copied nor stored. The network
// identity must be independently obtained from RPC by the caller.
func Chainbench(root, name, run, profile string, network Network) (Manifest, error) {
	m := Manifest{Format: ManifestFormat, Name: name, Run: run, Network: network, Clock: "unknown"}
	raw, err := readSmall(filepath.Join(root, "chain-record.json"))
	if err != nil {
		return m, err
	}
	var c struct {
		Version int `json:"formatVersion"`
		Nodes   []struct{ Label, LogPath string }
	}
	if json.Unmarshal(raw, &c) != nil || c.Version != 3 || len(c.Nodes) == 0 {
		return m, errors.New("unsupported chainbench record")
	}
	for i, n := range c.Nodes {
		if !filepath.IsAbs(n.LogPath) {
			n.LogPath = filepath.Join(root, n.LogPath)
		}
		m.Inputs = append(m.Inputs, File{ID: fmt.Sprintf("log-%d", i+1), Node: n.Label, Path: n.LogPath, Profile: profile})
	}
	return m, nil
}
func readSmall(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, errors.New("manifest exceeds 1MiB")
	}
	return b, nil
}

func Prepare(ctx context.Context, m Manifest) (Plan, error) {
	p := Plan{Manifest: m}
	if m.Format != ManifestFormat || !Identifier(m.Name) || !Identifier(m.Run) || len(m.Inputs) == 0 || len(m.Inputs) > 100 || decimal(m.Network.ChainID) == "" || !hashPattern.MatchString(m.Network.GenesisHash) {
		return p, errors.New("invalid run identity or inputs")
	}
	if m.Clock != "unknown" && m.Clock != "shared-host" && m.Clock != "ntp" {
		return p, errors.New("invalid clock model")
	}
	if (m.FromWall == "") != (m.ToWall == "") {
		return p, errors.New("run time bounds must be supplied together")
	}
	if m.FromWall != "" {
		var e1, e2 error
		p.From, e1 = time.Parse(time.RFC3339Nano, m.FromWall)
		p.To, e2 = time.Parse(time.RFC3339Nano, m.ToWall)
		if e1 != nil || e2 != nil || p.To.Before(p.From) {
			return p, errors.New("invalid run time window")
		}
		p.Manifest.FromWall = p.From.UTC().Format(time.RFC3339Nano)
		p.Manifest.ToWall = p.To.UTC().Format(time.RFC3339Nano)
	}
	ids := map[string]bool{}
	for _, f := range m.Inputs {
		if err := ctx.Err(); err != nil {
			return p, err
		}
		if !Identifier(f.ID) || !Identifier(f.Node) || ids[f.ID] {
			return p, errors.New("invalid or duplicate input ID")
		}
		ids[f.ID] = true
		var profile *Profile
		var err error
		switch f.Kind {
		case "", "log":
			profile, err = LoadProfile(f.Profile)
		case "events":
			if f.Profile != "" {
				return p, errors.New("event input uses the pinned schema, not a log profile")
			}
			hash := sha256.Sum256(schema.File())
			profile = &Profile{ID: EventProfile, SHA256: hex.EncodeToString(hash[:])}
		default:
			return p, errors.New("unsupported run input kind")
		}
		if err != nil {
			return p, err
		}
		file, err := os.Open(f.Path)
		if err != nil {
			return p, err
		}
		size, err := PrefixSize(file)
		if err != nil {
			file.Close()
			return p, err
		}
		h := sha256.New()
		_, err = io.Copy(h, &contextReader{ctx: ctx, r: io.NewSectionReader(file, 0, size)})
		file.Close()
		if err != nil {
			return p, err
		}
		sha := hex.EncodeToString(h.Sum(nil))
		if f.SHA256 != "" && f.SHA256 != sha {
			return p, errors.New("input checksum differs from manifest")
		}
		p.Inputs = append(p.Inputs, PreparedInput{Summary: InputSummary{Kind: f.Kind, ID: f.ID, Node: f.Node, Profile: profile.ID, ProfileSHA256: profile.SHA256, SHA256: sha, Bytes: size}, Path: f.Path, Profile: profile})
	}

	for i := range m.LegacyAssociations {
		d := &m.LegacyAssociations[i]
		d.Address = strings.ToLower(d.Address)
		if t, e := time.Parse(time.RFC3339Nano, d.From); e == nil {
			d.From = t.UTC().Format(time.RFC3339Nano)
		}
		if t, e := time.Parse(time.RFC3339Nano, d.To); e == nil {
			d.To = t.UTC().Format(time.RFC3339Nano)
		}
	}
	if err := validateLegacyAssociations(m.LegacyAssociations, p.Inputs); err != nil {
		return p, err
	}
	sort.Slice(p.Inputs, func(i, j int) bool { return p.Inputs[i].Summary.ID < p.Inputs[j].Summary.ID })
	inputs := []InputSummary{}
	for _, f := range p.Inputs {
		inputs = append(inputs, f.Summary)
	}
	eventsNormalizer := ""
	for _, in := range inputs {
		if in.Kind == "events" {
			eventsNormalizer = EventNormalizer
		}
	}
	p.Metadata, _ = json.Marshal(struct {
		EventsNormalizer   string              `json:"events_normalizer,omitempty"`
		LegacyAssociations []LegacyAssociation `json:"legacy_associations,omitempty"`
		Format             string              `json:"format"`
		Normalizer         string              `json:"normalizer"`
		Run                string              `json:"run"`
		Clock              string              `json:"clock"`
		From               string              `json:"from_t"`
		To                 string              `json:"to_t"`
		Inputs             []InputSummary
	}{eventsNormalizer, m.LegacyAssociations, m.Format, NormalizerVersion, m.Run, m.Clock, p.Manifest.FromWall, p.Manifest.ToWall, inputs})
	return p, nil
}

// PrefixSize snapshots complete lines of a regular file. New appended bytes
// belong to another dataset; a partial trailing line is excluded and visible
// through the captured byte count. The immutable prefix is verified again
// after normalization so an overwrite cannot silently change stored data.
func PrefixSize(f *os.File) (int64, error) {
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() || info.Size() > 10<<30 {
		return 0, errors.New("log input must be a regular file of at most 10GiB")
	}
	size := info.Size()
	if size == 0 {
		return 0, nil
	}
	tailSize := int64(4 << 20)
	if size < tailSize {
		tailSize = size
	}
	tail := make([]byte, tailSize)
	_, err = f.ReadAt(tail, size-tailSize)
	if err != nil {
		return 0, err
	}
	if pos := bytes.LastIndexByte(tail, '\n'); pos >= 0 {
		return size - tailSize + int64(pos) + 1, nil
	}
	// A complete final line without a newline is allowed for a closed file.
	// The parser verifies JSON, and the checksum detects any subsequent change.
	if size <= 4<<20 && json.Valid(bytes.TrimSpace(tail)) {
		return size, nil
	}
	return 0, errors.New("trailing log line exceeds 4MiB or input has no complete line")
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(b)
}
func (p Plan) Includes(wall string) bool {
	if p.From.IsZero() {
		return true
	}
	t, err := time.Parse(time.RFC3339Nano, wall)
	return err == nil && !t.Before(p.From) && !t.After(p.To)
}
func SafeNetwork(n Network) Network { n.GenesisHash = strings.ToLower(n.GenesisHash); return n }
