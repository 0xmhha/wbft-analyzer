package scenario

import (
	"errors"
	"sort"
	"strings"
)

type Issue struct {
	Node string `json:"node,omitempty"`
	Link string `json:"link,omitempty"`
	Code string `json:"code"`
}

type Assessment struct {
	Version string  `json:"version"`
	Status  string  `json:"status"`
	Issues  []Issue `json:"issues"`
}

// Assess keeps model coverage separate from a successful simulator run.
// Passing a synthetic run does not turn missing recorded evidence into a fit.
func Assess(nodes []Node, links []Link, runtimes []Runtime, app AppTiming) (Assessment, error) {
	out := Assessment{Version: FitVersion, Status: "complete", Issues: []Issue{}}
	if len(nodes) < 2 || len(nodes) > 256 {
		return out, errors.New("invalid assessment scope")
	}
	runtime := map[string]Runtime{}
	for _, r := range runtimes {
		if _, ok := runtime[strings.ToLower(r.Node)]; ok {
			return out, errors.New("duplicate runtime scope")
		}
		runtime[strings.ToLower(r.Node)] = r
	}
	known := map[string]bool{}
	for _, n := range nodes {
		addr := strings.ToLower(n.Address.Hex())
		if known[addr] {
			return out, errors.New("duplicate node assessment")
		}
		known[addr] = true
		r, ok := runtime[addr]
		if !ok || r.Starts == 0 || n.RuntimeEvidence != "verified" {
			out.Issues = append(out.Issues, Issue{Node: addr, Code: "runtime_unavailable"})
		}
		if ok && r.EngineStopped {
			out.Issues = append(out.Issues, Issue{Node: addr, Code: "engine_lifecycle_model_unavailable"})
		}
		if ok && (r.SignFloorState != "none" || r.SignFloor != nil) {
			out.Issues = append(out.Issues, Issue{Node: addr, Code: "sign_floor_model_unavailable"})
		}
	}
	if len(links) != len(nodes)*(len(nodes)-1) {
		out.Issues = append(out.Issues, Issue{Code: "directed_links_missing"})
	}
	seen := map[[2]string]bool{}
	for _, l := range links {
		l.Sender = strings.ToLower(l.Sender)
		l.Receiver = strings.ToLower(l.Receiver)
		if !known[strings.ToLower(l.Sender)] || !known[strings.ToLower(l.Receiver)] || l.Sender == l.Receiver || seen[[2]string{l.Sender, l.Receiver}] {
			return out, errors.New("invalid directed link assessment")
		}
		seen[[2]string{l.Sender, l.Receiver}] = true
		if l.Status != "complete" || l.Loss == nil || len(l.Delays) == 0 {
			out.Issues = append(out.Issues, Issue{Link: l.Sender + "/" + l.Receiver, Code: "link_model_unavailable"})
		}
	}
	builds, imports := map[string]int{}, map[string]int{}
	for which, samples := range [][]AppSample{app.Build, app.Import} {
		for _, sample := range samples {
			node := strings.ToLower(sample.Node)
			if !known[node] {
				return out, errors.New("application sample outside node scope")
			}
			if which == 0 {
				builds[node]++
			} else {
				imports[node]++
			}
		}
	}
	for _, node := range nodes {
		addr := strings.ToLower(node.Address.Hex())
		if _, ok := nodeApplicationPolicy(addr, app.Policies); !ok {
			out.Issues = append(out.Issues, Issue{Node: addr, Code: "application_policy_unavailable"})
		}
		if builds[addr] == 0 || imports[addr] == 0 {
			out.Issues = append(out.Issues, Issue{Node: addr, Code: "node_application_model_unavailable"})
		}
	}
	if app.Unsupported > 0 {
		out.Issues = append(out.Issues, Issue{Code: "application_lifecycle_model_unavailable"})
	}
	if len(app.Build) == 0 || len(app.Import) == 0 || app.Unproved > 0 {
		out.Issues = append(out.Issues, Issue{Code: "application_model_incomplete"})
	}
	if len(out.Issues) > 0 {
		out.Status = "partial"
	}
	sort.Slice(out.Issues, func(i, j int) bool {
		a, b := out.Issues[i], out.Issues[j]
		if a.Node != b.Node {
			return a.Node < b.Node
		}
		if a.Link != b.Link {
			return a.Link < b.Link
		}
		return a.Code < b.Code
	})
	return out, nil
}
