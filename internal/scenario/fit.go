package scenario

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	pairs "github.com/0xmhha/wbft-analyzer/internal/derive/messages"
	"github.com/0xmhha/wbft-analyzer/internal/source/messages"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/types"
)

// FitOptions contains already snapshotted local readers. None of their paths
// are retained in the fitted report or persisted experiment provenance.
type FitOptions struct {
	ProcessingPolicy    string
	ProcessingWorkers   int
	ProcessingTimings   []ProcessingTimings
	TransportEvidence   *TransportEvidence
	Model               string
	RuntimeObservations []RuntimeObservation
	WireMetric          string
	TransportInputs     []string
	Dataset             int64
	Chain               []byte
	Frames              []messages.Prepared
	Journals            []messages.Prepared
	Events              []EventInput
	Clock               pairs.Clock
	Coverage            []Coverage
	Runtime             []Node
	Origin              time.Time
	From, To            uint64
	Until               time.Duration
	CoreCommit          string
	Seeds               []int64
}

type Fitted struct {
	StaticConfiguration *StaticChainConfiguration `json:"static_configuration,omitempty"`
	WallOrigin          string                    `json:"wall_origin"`
	TransportScope      *TransportScope           `json:"transport_scope,omitempty"`
	Mode                string                    `json:"mode"`
	DeclaredModel       Assessment                `json:"declared_runtime_model"`
	Empirical           *EmpiricalProjection      `json:"empirical,omitempty"`
	RuntimeObservations []RuntimeBinding          `json:"runtime_observations"`
	WireMetric          string                    `json:"wire_metric"`
	TransportInputs     []Input                   `json:"transport_inputs"`
	Epochs              []RecordedEpoch           `json:"epochs"`
	Scope               ScopeCounts               `json:"scope"`
	NodeOptions         []Node                    `json:"node_options"`
	Provenance          Provenance                `json:"provenance"`
	SourceSHA256        string                    `json:"source_sha256"`
	Model               Assessment                `json:"model"`
	Links               []Link                    `json:"links"`
	Runtimes            []Runtime                 `json:"runtimes"`
	App                 AppTiming                 `json:"application"`
	Recorded            []Height                  `json:"recorded"`
	Scenario            *sim.Scenario             `json:"-"`
}

// Fit derives one prepared network experiment from exact chain and journal
// snapshots plus verified event inputs. Unsupported source gaps remain a
// structured partial fit rather than being filled by simulator defaults.
func Fit(ctx context.Context, o FitOptions) (Fitted, error) {
	if !ValidModel(o.Model) {
		return Fitted{}, errors.New("unsupported scenario model")
	}
	if o.Model == "" {
		o.Model = DeclaredRuntimeModel
	}
	if !ValidProcessing(o.ProcessingPolicy, o.ProcessingWorkers) || o.ProcessingPolicy != "" && o.Model != EmpiricalCoreModel {
		return Fitted{}, errors.New("invalid explicit processing policy")
	}
	if o.WireMetric == "" {
		o.WireMetric = "link"
	}
	if !ValidWireMetric(o.WireMetric) {
		return Fitted{}, errors.New("unsupported wire measurement")
	}
	out := Fitted{WallOrigin: o.Origin.UTC().Format(time.RFC3339Nano), App: AppTiming{Policies: []ApplicationPolicy{}}, Links: []Link{}, Runtimes: []Runtime{}, Recorded: []Height{}, Model: Assessment{Version: FitVersion, Status: "partial", Issues: []Issue{}}}
	out.WireMetric = o.WireMetric
	out.Mode = o.Model
	if len(o.Runtime) > 0 {
		return out, errors.New("runtime policy must come from recorded engine starts")
	}
	if len(o.Chain) == 0 || len(o.Chain) > 64<<20 || len(o.Journals) == 0 || len(o.Journals) > 256 || o.Origin.IsZero() || o.Clock.SkewMS < 0 || o.Clock.SkewMS > 3600000 {
		return out, errors.New("invalid recorded fitting scope")
	}
	blocks, err := sim.DecodeChain(o.Chain)
	if err != nil || len(blocks) < 3 {
		return out, errors.New("recorded chain unavailable")
	}
	if blocks[0] == nil || blocks[0].Header == nil {
		return out, errors.New("genesis header unavailable")
	}
	genesis := codec.BlockHash(blocks[0].Header).Hex()
	sources := []Input{}
	nodes := []Node{}
	inputs := []MessageInput{}
	var config *types.Config
	for _, p := range o.Journals {
		var nodeAddress types.Address
		if err := nodeAddress.UnmarshalText([]byte(p.Summary.Node)); err != nil {
			return out, errors.New("invalid journal node address")
		}
		node, cfg, err := InspectNodeOptions(ctx, p.Input.Path, nodeAddress)
		if err != nil {
			return out, err
		}
		if config == nil {
			config = cfg
		} else if config.ChainID == nil || cfg.ChainID == nil || config.ChainID.Cmp(cfg.ChainID) != 0 {
			return out, errors.New("journal network mismatch")
		}
		if !reflect.DeepEqual(config, cfg) {
			return out, errors.New("per-node chain configuration requires explicit fitting")
		}
		if cfg.ChainID == nil {
			return out, errors.New("chain ID unavailable")
		}
		input, err := InspectMessageSnapshot(ctx, p, cfg.ChainID.String(), genesis)
		if err != nil {
			return out, err
		}
		nodes = append(nodes, node)
		inputs = append(inputs, input)
		sources = append(sources, input.Source)
	}
	if len(o.Frames) > 256 || len(o.Frames)+len(o.Journals) > 256 {
		return out, errors.New("message source scope exceeds bound")
	}
	for _, p := range o.Frames {
		if p.Summary.Kind != "frames" || config == nil {
			return out, errors.New("invalid frame fitting source")
		}
		input, err := InspectMessageSnapshot(ctx, p, config.ChainID.String(), genesis)
		if err != nil {
			return out, err
		}
		inputs = append(inputs, input)
		sources = append(sources, input.Source)
	}
	facts, err := InspectChain(blocks, config, o.From, o.To)
	if err != nil {
		out.Model.Issues = append(out.Model.Issues, Issue{Code: "chain_model_unavailable"})
		return out, err
	}
	out.Recorded = facts.Heights
	out.StaticConfiguration = facts.StaticConfiguration
	out.Epochs = facts.Epochs
	out.Model.Issues = append(out.Model.Issues, facts.Issues...)
	ordered := []Node{}
	addresses := []string{}
	for _, a := range facts.Validators {
		addr := strings.ToLower(a.Hex())
		addresses = append(addresses, addr)
		found := false
		for _, n := range nodes {
			if n.Address == a {
				ordered = append(ordered, n)
				found = true
				break
			}
		}
		if !found {
			ordered = append(ordered, Node{Address: a})
			out.Model.Issues = append(out.Model.Issues, Issue{Node: addr, Code: "node_options_unavailable"})
		}
	}
	transport, err := selectTransportInputs(inputs, o.TransportInputs, addresses)
	if err != nil {
		return out, err
	}
	out.TransportInputs = []Input{}
	transportIDs := []string{}
	for _, input := range transport {
		out.TransportInputs = append(out.TransportInputs, input.Source)
		transportIDs = append(transportIDs, input.Source.ID)
	}
	if o.TransportEvidence != nil {
		if o.Model != EmpiricalCoreModel || o.Clock.Model != "shared-host" || o.Clock.SkewMS != 0 || len(o.Coverage) != 0 {
			return out, errors.New("closed observer scope requires empirical shared-host inputs without separate coverage overrides")
		}
		scope, coverage, e := BindTransportScope(*o.TransportEvidence, transport, o.Events, blocks, addresses, o.Origin, o.Until)
		if e != nil {
			return out, e
		}
		if scope.ThroughHeight <= o.To {
			return out, errors.New("closed observer cutoff does not cover the fitting child height")
		}
		out.TransportScope = &scope
		o.Coverage = coverage
		sources = append(sources, scope.Sources...)
	}
	endpoints, err := PairMessageInputsMetric(transport, o.Clock, o.WireMetric)
	if err != nil {
		return out, err
	}
	endpoints, linkScope, err := ScopeLinks(endpoints, o.From, o.To)
	if err != nil {
		return out, err
	}
	out.Scope.LinksExcluded, out.Scope.LinksUnscoped = linkScope.LinksExcluded, linkScope.LinksUnscoped
	out.Links, err = FitLinksMetric(addresses, endpoints, o.Coverage, o.Clock.Model, time.Duration(o.Clock.SkewMS)*time.Millisecond, o.WireMetric)
	if err != nil {
		return out, err
	}
	allEvents := []EventInput{}
	eventIDs := map[string]bool{}
	for _, input := range o.Events {
		if eventIDs[input.Source.ID] || !hexLength(input.Source.SHA256, 64) || input.Stats.SHA256 != input.Source.SHA256 || input.Stats.Malformed > 0 || input.Stats.SequenceGaps > 0 {
			return out, errors.New("unverified fitting event input")
		}
		eventIDs[input.Source.ID] = true
		allEvents = append(allEvents, input)
		sources = append(sources, input.Source)
	}
	for i, n := range ordered {
		selected := []EventInput{}
		for _, input := range allEvents {
			if strings.EqualFold(input.Source.Node, n.Address.Hex()) {
				selected = append(selected, input)
			}
		}
		if len(selected) != 1 {
			out.Model.Issues = append(out.Model.Issues, Issue{Node: strings.ToLower(n.Address.Hex()), Code: "runtime_input_unavailable"})
			continue
		}
		policies, err := FitApplicationPolicies(selected[0].Source.Node, selected[0].Source.ID, selected[0].Records)
		if err != nil {
			return out, err
		}
		if len(out.App.Policies)+len(policies) > 256 {
			return out, errors.New("application policy history exceeds bound")
		}
		out.App.Policies = append(out.App.Policies, policies...)
		runtime, err := FitRuntime(selected[0].Source.Node, selected[0].Source.ID, selected[0].Records, o.Origin)
		if err != nil {
			out.Model.Issues = append(out.Model.Issues, Issue{Node: runtime.Node, Code: "runtime_model_unavailable"})
			continue
		}
		out.Runtimes = append(out.Runtimes, runtime)
		if runtime.ReplayWAL != nil {
			ordered[i].RuntimeEvidence = "verified"
			ordered[i].ReplayWAL = *runtime.ReplayWAL
			ordered[i].SignFloor = runtime.SignFloor
			ordered[i].RuntimeInput = selected[0].Source.ID
			ordered[i].RuntimeLine = runtime.WALPolicies[0].Line
		}

		appEvents, appScope, err := ScopeApplication(selected[0].Records, o.From, o.To)
		if err != nil {
			return out, err
		}
		out.Scope.AppExcluded += appScope.AppExcluded
		out.Scope.AppUnscoped += appScope.AppUnscoped
		timing, err := FitAppTiming(appEvents)
		if err != nil {
			return out, err
		}
		out.App.Build = append(out.App.Build, timing.Build...)
		out.App.Import = append(out.App.Import, timing.Import...)
		out.App.Unproved += timing.Unproved
		out.App.Unsupported += timing.Unsupported
		out.App.Outcomes = append(out.App.Outcomes, timing.Outcomes...)
	}
	out.RuntimeObservations = []RuntimeBinding{}
	if len(o.RuntimeObservations) > 256 {
		return out, errors.New("runtime source scope exceeds bound")
	}
	runtimeNodes := map[string]bool{}
	for _, in := range o.RuntimeObservations {
		if runtimeNodes[in.Source.Node] {
			return out, errors.New("duplicate runtime node source")
		}
		runtimeNodes[in.Source.Node] = true
		binding, e := BindRuntimeObservation(in, config, addresses)
		if e != nil {
			return out, e
		}
		out.RuntimeObservations = append(out.RuntimeObservations, binding)
		sources = append(sources, in.Source)
		out.Model.Issues = append(out.Model.Issues, Issue{Node: in.Source.Node, Code: "observed_runtime_execution_model_unavailable"})
		if binding.Configuration != "startup_scalars_verified" {
			out.Model.Issues = append(out.Model.Issues, Issue{Node: in.Source.Node, Code: "observed_runtime_configuration_unverified"})
		}
	}
	out.NodeOptions = append([]Node(nil), ordered...)
	assessment, err := Assess(ordered, out.Links, out.Runtimes, out.App)
	if err != nil {
		return out, err
	}
	assessment.Issues = append(assessment.Issues, out.Model.Issues...)
	if out.Scope.LinksUnscoped > 0 || out.Scope.AppUnscoped > 0 {
		assessment.Issues = append(assessment.Issues, Issue{Code: "fitting_height_scope_unavailable"})
	}
	if len(assessment.Issues) > 0 {
		assessment.Status = "partial"
	}
	out.Model = assessment
	out.DeclaredModel = assessment
	buildNodes, buildRuntimes, buildApp := ordered, out.Runtimes, out.App
	if o.Model == EmpiricalCoreModel {
		projection, issues, e := fitEmpiricalProjection(o, out, sources)
		if e != nil {
			return out, e
		}
		if out.TransportScope != nil {
			projection.Assumptions = append(projection.Assumptions, out.TransportScope.Assumptions...)
		}
		out.Empirical = &projection
		assessment = assessEmpirical(projection, out.Links, o.Until)
		assessment.Issues = append(assessment.Issues, facts.Issues...)
		assessment.Issues = append(assessment.Issues, issues...)
		if out.Scope.LinksUnscoped > 0 || out.Scope.AppUnscoped > 0 {
			assessment.Issues = append(assessment.Issues, Issue{Code: "fitting_height_scope_unavailable"})
		}
		if len(assessment.Issues) > 0 {
			assessment.Status = "partial"
		}
		orderIssues(assessment.Issues)
		out.Model = assessment
		buildNodes = []Node{}
		for _, node := range projection.Nodes {
			buildNodes = append(buildNodes, node.Options)
		}
		buildRuntimes, buildApp = projection.Runtimes, projection.Application
	}
	processing, processingIssues, err := fitProcessingModel(o, sources, buildNodes)
	if err != nil {
		return out, err
	}
	assessment.Processing = processing
	assessment.Issues = append(assessment.Issues, processingIssues...)
	if len(processingIssues) > 0 {
		assessment.Status = "partial"
	}
	orderIssues(assessment.Issues)
	out.Model = assessment
	if processing != nil && out.Empirical != nil {
		assumptions := []string{}
		for _, assumption := range out.Empirical.Assumptions {
			if assumption != "receive_checks_and_core_steps_consume_no_simulated_time" {
				assumptions = append(assumptions, assumption)
			}
		}
		out.Empirical.Assumptions = append(assumptions, processing.Assumptions...)
	}
	modelRaw, err := json.Marshal(struct {
		Processing         *ProcessingModel
		HeaderTimeBaseline string
		TransportScope     *TransportScope
		Mode               string
		Empirical          *EmpiricalProjection
		WireMetric         string
		TransportInputs    []Input
		From, To           uint64
		Origin             string
		UntilNS            int64
		Clock              pairs.Clock
		Coverage           []Coverage
		Nodes              []Node
		Params             sim.Params
		Links              []Link
		Runtimes           []Runtime
		Application        AppTiming
		Scope              ScopeCounts
		GenesisCount       int
		Epochs             []RecordedEpoch
		ObservedRuntime    []RuntimeBinding
	}{processing, HeaderTimeBaselineMethod, out.TransportScope, o.Model, out.Empirical, o.WireMetric, out.TransportInputs, o.From, o.To, o.Origin.UTC().Format(time.RFC3339Nano), int64(o.Until), o.Clock, o.Coverage, ordered, facts.Params, out.Links, out.Runtimes, out.App, out.Scope, facts.GenesisCount, facts.Epochs, out.RuntimeObservations})
	if err != nil {
		return out, err
	}
	modelHash := sha256.Sum256(modelRaw)
	sum := sha256.Sum256(o.Chain)
	provenance := Provenance{Mode: o.Model, TransportInputs: transportIDs, ModelSHA256: hex.EncodeToString(modelHash[:]), Dataset: o.Dataset, Version: FitVersion, Inputs: sources, ChainSHA256: hex.EncodeToString(sum[:]), CoreCommit: o.CoreCommit, Seeds: o.Seeds}
	if out.Empirical != nil {
		provenance.Assumptions = out.Empirical.Assumptions
		for _, node := range out.Empirical.Nodes {
			if node.Substituted && node.Source.ID != "" {
				provenance.Substitutions = append(provenance.Substitutions, CoreSubstitution{Node: node.Node, Source: node.Source, Policy: "all_improvements_off", SigningState: node.SigningState})
			}
		}
	}
	out.Provenance, out.SourceSHA256, err = SealProvenance(provenance)
	if err != nil {
		return out, err
	}
	if assessment.Status != "complete" {
		return out, nil
	}
	sc, err := buildScenario(buildNodes, out.Links, facts.Params, []time.Duration{0}, []time.Duration{0}, sim.Stop{Height: o.To, Duration: o.Until}, o.Model)
	if err != nil {
		return out, err
	}
	sc.WallOrigin = o.Origin.UTC().Round(0)
	sc, err = ApplyRuntime(sc, buildNodes, buildRuntimes)
	if err != nil {
		return out, err
	}
	if out.TransportScope != nil {
		sc, err = ApplyTransportSessions(sc, buildNodes, *out.TransportScope, o.Origin)
		if err != nil {
			return out, err
		}
	}
	sc, err = ApplyEpochs(sc, facts.Validators, facts.GenesisCount, facts.Epochs)
	if err != nil {
		return out, err
	}
	sc, err = ApplyAppTiming(sc, buildNodes, buildApp)
	if err != nil {
		return out, err
	}
	if o.Model == DeclaredRuntimeModel {
		sc, err = ApplyApplicationPolicies(sc, ordered, out.App.Policies)
		if err != nil {
			return out, err
		}
	}
	sc, err = applyProcessing(sc, buildNodes, out.Model.Processing)
	if err != nil {
		return out, err
	}
	out.Scenario = &sc
	return out, nil
}
