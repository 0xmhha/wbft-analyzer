package scenario

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/0xmhha/wbft-analyzer/internal/source/jsonmeta"
	"github.com/0xmhha/wbft-analyzer/internal/source/logs"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/observe/event"
	"github.com/0xmhha/wbft/types"
)

// EvidenceDocument is private immutable source material, never API metadata.
type EvidenceDocument struct {
	Source Input
	Bytes  []byte
}
type TransportWindowEvidence struct {
	Input       string
	Certificate EvidenceDocument
}
type TransportEvidence struct {
	Declaration Input
	Controller  EvidenceDocument
	Headers     []EvidenceDocument
	Windows     []TransportWindowEvidence
}

type TransportScope struct {
	ThroughHeight          uint64             `json:"through_height,string"`
	Status                 string             `json:"status"`
	Controller             Input              `json:"controller"`
	Sources                []Input            `json:"sources"`
	Cutoff                 time.Time          `json:"cutoff"`
	PhysicalDeliveryProven bool               `json:"physical_delivery_proven"`
	Assumptions            []string           `json:"assumptions"`
	Windows                []TransportWindow  `json:"windows"`
	Sessions               []TransportSession `json:"sessions"`
}
type TransportWindow struct {
	Input          string    `json:"input"`
	Certificate    Input     `json:"certificate"`
	Node           string    `json:"node"`
	Run            string    `json:"run"`
	From           time.Time `json:"from"`
	To             time.Time `json:"to"`
	SettledThrough time.Time `json:"settled_through"`
	FrameSHA       string    `json:"frame_sha256"`
}
type TransportSession struct {
	Input    string    `json:"input"`
	Node     string    `json:"node"`
	Peer     string    `json:"peer"`
	Run      string    `json:"run"`
	From     time.Time `json:"from"`
	To       time.Time `json:"to"`
	FromLine int64     `json:"from_line"`
	ToLine   int64     `json:"to_line"`
}

type transportController struct {
	Format    string   `json:"format"`
	Status    string   `json:"status"`
	Addresses []string `json:"addresses"`
	Stopped   *bool    `json:"nodes_stopped"`
	Exits     []*int   `json:"process_exit_codes"`
	Launches  []struct {
		At   time.Time `json:"at"`
		Node *int      `json:"node"`
		PID  *uint64   `json:"pid"`
		Kind string    `json:"kind"`
		Env  struct {
			Node string `json:"WBFT_TAP_NODE"`
		} `json:"instrumentation_env"`
	} `json:"launches"`
	Phases []struct {
		Name  string    `json:"name"`
		At    time.Time `json:"at"`
		Heads []uint64  `json:"heads"`
	} `json:"phases"`
	Verified struct {
		First *uint64 `json:"first"`
		Last  *uint64 `json:"last"`
		Equal *bool   `json:"all_node_hashes_equal"`
	} `json:"verified_heights"`
}
type recordingCertificate struct {
	Format        string    `json:"format"`
	Scope         string    `json:"scope"`
	Node          string    `json:"node"`
	Run           string    `json:"run"`
	From          time.Time `json:"start_wall"`
	To            time.Time `json:"end_wall"`
	FrameSHA      string    `json:"frame_sha256"`
	Complete      *bool     `json:"recording_complete"`
	Writer        *bool     `json:"writer_success"`
	Physical      *bool     `json:"delivery_coverage_proven"`
	Attempts      string    `json:"frame_attempts"`
	Dropped       string    `json:"frame_dropped"`
	Incomplete    string    `json:"frame_incomplete"`
	Active        string    `json:"streams_active"`
	PendingReads  string    `json:"pending_reads"`
	PendingWrites string    `json:"pending_writes"`
	Opened        string    `json:"streams_opened"`
	Closed        string    `json:"streams_closed"`
}

var errTransportScope = errors.New("unverified closed transport recording scope")

func evidenceJSON(d EvidenceDocument, kind string, limit int, strict bool, dst any) error {
	sum := sha256.Sum256(d.Bytes)
	if !logs.Identifier(d.Source.ID) || d.Source.Kind != kind || !hexLength(d.Source.SHA256, 64) || hex.EncodeToString(sum[:]) != d.Source.SHA256 {
		return errTransportScope
	}
	if jsonmeta.Decode(d.Bytes, limit, strict, dst) != nil {
		return errTransportScope
	}
	return nil
}

// BindTransportScope derives bounded observer coverage from retained original
// certificates, frame streams, controller exits/cutoff and header copies. The
// controller attests process state; hashes establish identity, not authenticity.
// No recording certificate is promoted to a physical network delivery proof.
func BindTransportScope(e TransportEvidence, inputs []MessageInput, events []EventInput, blocks []*types.Block, nodes []string, origin time.Time, until time.Duration) (TransportScope, []Coverage, error) {
	out := TransportScope{Status: "unverified", Controller: e.Controller.Source, Sources: []Input{e.Declaration, e.Controller.Source}, Assumptions: []string{"controller_attests_process_exit_and_capture_cutoff", "closed_receiver_recording_is_not_physical_delivery_proof", "outbound_links_enabled_only_in_local_observer_sessions", "peer_info_lists_all_other_live_nodes", "in_flight_delivery_dropped_if_session_closes", "session_boundary_clock_uncertainty_not_modeled"}, Windows: []TransportWindow{}, Sessions: []TransportSession{}}
	coverage := []Coverage{}
	if len(nodes) < 2 || len(nodes) > 256 || e.Declaration.Kind != "transport-manifest" || e.Declaration.Node != "network" || !logs.Identifier(e.Declaration.ID) || !hexLength(e.Declaration.SHA256, 64) || e.Controller.Source.Node != "network" || len(e.Headers) != len(nodes) || len(e.Windows) < len(nodes) || len(e.Windows) > 256 || until <= 0 || until > 24*time.Hour || origin.IsZero() {
		return out, nil, errTransportScope
	}
	var ctl transportController
	// Controller and RPC objects contain private operational fields. Only this
	// bounded typed subset is interpreted; their full bytes remain private CAS.
	if evidenceJSON(e.Controller, "transport-controller", 1<<20, false, &ctl) != nil || ctl.Format != "wbft-local-takeover-case/1" || ctl.Status != "recording_windows_verified" || ctl.Stopped == nil || !*ctl.Stopped || len(ctl.Addresses) != len(nodes) || len(ctl.Launches) != len(e.Windows) || len(ctl.Exits) != len(ctl.Launches) || ctl.Verified.First == nil || *ctl.Verified.First != 0 || ctl.Verified.Last == nil || *ctl.Verified.Last >= uint64(len(blocks)) || ctl.Verified.Equal == nil || !*ctl.Verified.Equal {
		return out, nil, errTransportScope
	}
	out.ThroughHeight = *ctl.Verified.Last
	known := map[string]bool{}
	for _, n := range nodes {
		if n != strings.ToLower(n) || known[n] {
			return out, nil, errTransportScope
		}
		known[n] = true
	}
	seen := map[string]bool{}
	for _, n := range ctl.Addresses {
		if !known[n] || seen[n] {
			return out, nil, errTransportScope
		}
		seen[n] = true
	}
	for _, phase := range ctl.Phases {
		if phase.Name == "captured" {
			if !out.Cutoff.IsZero() || len(phase.Heads) != len(nodes) || phase.At.Before(origin) || phase.At.After(origin.Add(24*time.Hour)) {
				return out, nil, errTransportScope
			}
			for _, h := range phase.Heads {
				if h != *ctl.Verified.Last {
					return out, nil, errTransportScope
				}
			}
			out.Cutoff = phase.At
		}
	}
	if out.Cutoff.IsZero() {
		return out, nil, errTransportScope
	}
	headerNodes := map[string]bool{}
	for _, doc := range e.Headers {
		node := doc.Source.Node
		if !known[node] || headerNodes[node] {
			return out, nil, errTransportScope
		}
		headerNodes[node] = true
		var hs []struct {
			Number string `json:"number"`
			Hash   string `json:"hash"`
		}
		if evidenceJSON(doc, "transport-headers", 64<<20, false, &hs) != nil || len(hs) != int(*ctl.Verified.Last)+1 {
			return out, nil, errTransportScope
		}
		for i, h := range hs {
			num, err := strconv.ParseUint(strings.TrimPrefix(h.Number, "0x"), 16, 64)
			if err != nil || !strings.HasPrefix(h.Number, "0x") || num != uint64(i) || h.Hash != strings.ToLower(codec.BlockHash(blocks[i].Header).Hex()) {
				return out, nil, errTransportScope
			}
		}
		out.Sources = append(out.Sources, doc.Source)
	}
	selected := map[string]MessageInput{}
	for _, in := range inputs {
		if in.Source.Kind != "frames" || !known[in.Source.Node] {
			return out, nil, errTransportScope
		}
		selected[in.Source.ID] = in
	}
	seenRuns := map[string]bool{}
	seenPIDs := map[uint64]bool{}
	for _, entry := range e.Windows {
		var c recordingCertificate
		if evidenceJSON(entry.Certificate, "transport-certificate", 64<<10, true, &c) != nil || c.Format != "wbft-transport-recording-window/1" || c.Scope != "recording_window_only" || c.Complete == nil || !*c.Complete || c.Writer == nil || !*c.Writer || c.Physical == nil || *c.Physical || !known[c.Node] || entry.Certificate.Source.Node != c.Node || seenRuns[c.Run] || c.From.IsZero() || !c.To.After(c.From) || c.To.After(origin.Add(24*time.Hour)) || !hexLength(c.FrameSHA, 64) {
			return out, nil, errTransportScope
		}
		seenRuns[c.Run] = true
		for _, n := range []string{c.Dropped, c.Incomplete, c.Active, c.PendingReads, c.PendingWrites} {
			if n != "0" {
				return out, nil, errTransportScope
			}
		}
		attempts, err := canonicalCount(c.Attempts)
		if err != nil || attempts == 0 || attempts > 1000000 {
			return out, nil, errTransportScope
		}
		opened, err := canonicalCount(c.Opened)
		if err != nil || opened == 0 || c.Opened != c.Closed {
			return out, nil, errTransportScope
		}
		in, ok := selected[entry.Input]
		if !ok || in.Source.Node != c.Node {
			return out, nil, errTransportScope
		}
		frame := ""
		for _, f := range in.Files {
			if f.SHA256 == c.FrameSHA {
				if frame != "" {
					return out, nil, errTransportScope
				}
				frame = f.Name
			}
		}
		if frame == "" {
			return out, nil, errTransportScope
		}
		var rows []int
		for i, r := range in.Records {
			if r.Run == c.Run {
				if r.File != frame {
					return out, nil, errTransportScope
				}
				rows = append(rows, i)
			}
		}
		if uint64(len(rows)) != attempts {
			return out, nil, errTransportScope
		}
		active := map[string]uint64{}
		began := map[string]TransportSession{}
		var opens, closes, frames uint64
		for i, index := range rows {
			r := in.Records[index]
			at, err := time.Parse(time.RFC3339Nano, r.Wall)
			if err != nil || at.Before(c.From) || at.After(c.To) || r.Seq != strconv.Itoa(i) || r.Ordinal != int64(i+1) || !known[r.Peer] || r.Peer == c.Node {
				return out, nil, errTransportScope
			}
			switch r.Type {
			case "conn":
				switch r.Event {
				case "istanbul_attached":
					if active[r.Peer] == 0 {
						began[r.Peer] = TransportSession{Input: entry.Input, Node: c.Node, Peer: r.Peer, Run: c.Run, From: at, FromLine: r.Ordinal}
					}
					active[r.Peer]++
					opens++
				case "closed":
					if active[r.Peer] == 0 {
						return out, nil, errTransportScope
					}
					active[r.Peer]--
					closes++
					if active[r.Peer] == 0 {
						s := began[r.Peer]
						if at.Before(s.From) {
							return out, nil, errTransportScope
						}
						s.To = at
						s.ToLine = r.Ordinal
						if len(out.Sessions) >= 65536 {
							return out, nil, errTransportScope
						}
						out.Sessions = append(out.Sessions, s)
						delete(began, r.Peer)
					}
				default:
					return out, nil, errTransportScope
				}
			case "frame":
				frames++
				if r.IO == nil || r.PayloadSHA256 == "" || r.Decode == "missing_payload" || r.Decode == "oversized" {
					return out, nil, errTransportScope
				}
				start, err := time.Parse(time.RFC3339Nano, r.IO.StartWall)
				if err != nil || start.Before(c.From) {
					return out, nil, errTransportScope
				}
				end, err := time.Parse(time.RFC3339Nano, r.IO.EndWall)
				if err != nil || end.Before(start) || end.After(c.To) {
					return out, nil, errTransportScope
				}
			default:
				return out, nil, errTransportScope
			}
		}
		if frames == 0 || opens != opened || closes != opened || len(began) != 0 {
			return out, nil, errTransportScope
		}
		byPeer := map[string][]TransportSession{}
		for _, session := range out.Sessions {
			if session.Run == c.Run {
				byPeer[session.Peer] = append(byPeer[session.Peer], session)
			}
		}
		for peer := range byPeer {
			sort.Slice(byPeer[peer], func(i, j int) bool { return byPeer[peer][i].From.Before(byPeer[peer][j].From) })
		}
		for _, index := range rows {
			r := in.Records[index]
			if r.Type != "frame" {
				continue
			}
			start, _ := time.Parse(time.RFC3339Nano, r.IO.StartWall)
			sessions := byPeer[r.Peer]
			at := sort.Search(len(sessions), func(i int) bool { return sessions[i].From.After(start) }) - 1
			if at < 0 || start.After(sessions[at].To) {
				return out, nil, errTransportScope
			}
		}

		parts := strings.Split(c.Run, "-")
		if len(parts) != 3 || parts[0] != "tap" {
			return out, nil, errTransportScope
		}
		pid, err := canonicalCount(parts[1])
		if err != nil || pid == 0 || seenPIDs[pid] {
			return out, nil, errTransportScope
		}
		seenPIDs[pid] = true
		stamp, err := canonicalCount(parts[2])
		if err != nil || c.From.UnixNano() < 0 || stamp != uint64(c.From.UnixNano()) {
			return out, nil, errTransportScope
		}
		launchIndex := -1
		for i, l := range ctl.Launches {
			if l.PID != nil && *l.PID == pid {
				if launchIndex >= 0 {
					return out, nil, errTransportScope
				}
				launchIndex = i
			}
		}
		if launchIndex < 0 {
			return out, nil, errTransportScope
		}
		l := ctl.Launches[launchIndex]
		if l.Node == nil || *l.Node < 0 || *l.Node >= len(ctl.Addresses) || ctl.Addresses[*l.Node] != c.Node || l.Env.Node != c.Node || l.At.IsZero() || l.At.After(c.From) || ctl.Exits[launchIndex] == nil || *ctl.Exits[launchIndex] != 0 || l.Kind != "legacy" && l.Kind != "gstable" && l.Kind != "native" {
			return out, nil, errTransportScope
		}
		if l.Kind == "native" {
			if _, _, err := nativeWindow(c.Node, c.From, c.To, events); err != nil {
				return out, nil, err
			}
		}
		settled := out.Cutoff
		if settled.After(c.To) {
			settled = c.To
		}
		if !settled.After(c.From) {
			return out, nil, errTransportScope
		}
		out.Windows = append(out.Windows, TransportWindow{Input: entry.Input, Certificate: entry.Certificate.Source, Node: c.Node, Run: c.Run, From: c.From, To: c.To, SettledThrough: settled, FrameSHA: c.FrameSHA})
		coverage = append(coverage, Coverage{Node: c.Node, From: c.From, To: c.To, SettledThrough: settled, Complete: true})
		out.Sources = append(out.Sources, entry.Certificate.Source)
	}
	for _, node := range nodes {
		ws := []TransportWindow{}
		for _, w := range out.Windows {
			if w.Node == node {
				ws = append(ws, w)
			}
		}
		sort.Slice(ws, func(i, j int) bool { return ws[i].From.Before(ws[j].From) })
		if len(ws) == 0 || ws[len(ws)-1].From.After(out.Cutoff) || !ws[len(ws)-1].To.After(out.Cutoff) {
			return out, nil, errTransportScope
		}
		for i := 1; i < len(ws); i++ {
			if ws[i].From.Before(ws[i-1].To) {
				return out, nil, errTransportScope
			}
			_, stop, err := nativeWindow(node, ws[i-1].From, ws[i-1].To, events)
			if err != nil {
				return out, nil, err
			}
			start, _, err := nativeWindow(node, ws[i].From, ws[i].To, events)
			if err != nil || stop.After(ws[i-1].To) || start.Before(ws[i].From) {
				return out, nil, errTransportScope
			}
		}
	}
	out.Status = "closed_observer_scope"
	return out, coverage, nil
}

func canonicalCount(s string) (uint64, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != s {
		return 0, errTransportScope
	}
	return n, nil
}

func nativeWindow(node string, from, to time.Time, inputs []EventInput) (time.Time, time.Time, error) {
	var start, stop time.Time
	writer := ""
	for _, in := range inputs {
		if in.Source.Node != node {
			continue
		}
		if in.Stats.SHA256 != in.Source.SHA256 || in.Stats.Malformed != 0 || in.Stats.SequenceGaps != 0 {
			return start, stop, errTransportScope
		}
		for _, r := range in.Records {
			if r.Record.Kind != event.NodeStart && r.Record.Kind != event.NodeStop {
				continue
			}
			at, err := time.Parse(time.RFC3339Nano, r.Wall)
			if err != nil {
				return start, stop, errTransportScope
			}
			if at.Before(from) || at.After(to) {
				continue
			}
			if r.Record.Kind == event.NodeStart {
				if !start.IsZero() || r.Run == "" {
					return start, stop, errTransportScope
				}
				start = at
				writer = r.Run
			} else {
				if !stop.IsZero() || writer != r.Run {
					return start, stop, errTransportScope
				}
				stop = at
			}
		}
	}
	if start.IsZero() || stop.IsZero() || stop.Before(start) {
		return start, stop, errTransportScope
	}
	return start, stop, nil
}

// ApplyTransportSessions models local outbound availability. Peers() retains
// the simulator's all-live-node policy. In-flight drops at a closing boundary
// and unmodeled boundary uncertainty are explicit empirical assumptions.
func ApplyTransportSessions(sc sim.Scenario, nodes []Node, scope TransportScope, origin time.Time) (sim.Scenario, error) {
	if scope.Status != "closed_observer_scope" || scope.PhysicalDeliveryProven || len(nodes) != len(sc.Validators) || len(sc.Partitions) > 0 {
		return sc, errTransportScope
	}
	sc.Partitions = []sim.Partition{}
	byPair := map[[2]string][]TransportSession{}
	for _, session := range scope.Sessions {
		key := [2]string{strings.ToLower(session.Node), strings.ToLower(session.Peer)}
		byPair[key] = append(byPair[key], session)
	}
	for i, a := range nodes {
		for j, b := range nodes {
			if i == j {
				continue
			}
			windows := [][2]time.Duration{}
			for _, s := range byPair[[2]string{strings.ToLower(a.Address.Hex()), strings.ToLower(b.Address.Hex())}] {
				from, to := s.From.Sub(origin), s.To.Sub(origin)
				if to <= 0 || from >= sc.Until.Duration {
					continue
				}
				from = max(from, 0)
				to = min(to, sc.Until.Duration)
				if to < from {
					return sc, errTransportScope
				}
				windows = append(windows, [2]time.Duration{from, to})
			}
			if len(windows) == 0 {
				return sc, fmt.Errorf("directed observer session unavailable: %w", errTransportScope)
			}
			sort.Slice(windows, func(i, j int) bool { return windows[i][0] < windows[j][0] })
			cursor := time.Duration(0)
			cut := func(from, to time.Duration) {
				if to > from {
					sc.Partitions = append(sc.Partitions, sim.Partition{From: from, To: to, DirectedCut: [][2]types.Address{{sc.Validators[i].Address(), sc.Validators[j].Address()}}})
				}
			}
			for _, w := range windows {
				if w[0] < cursor {
					return sc, errTransportScope
				}
				cut(cursor, w[0])
				cursor = w[1]
			}
			cut(cursor, sc.Until.Duration)
		}
	}
	return sc, nil
}
