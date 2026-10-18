import { useState } from "react";
import { get, type Schemas } from "../api/client";
import { activationWindows } from "../activationWindows";
import { phaseEvidenceLink } from "../phaseComparison";
import { Pending, useLoad } from "../ui";
import { seconds } from "./PhaseLatency";
import { PhaseComparisonBands } from "./RunPhaseComparison";

const metrics = ["preprepare", "prepare_quorum", "commit_quorum", "commit", "import", "round_to_decision", "round_to_import"];
type Query = { capture: number; key: string; before: number; after: number; metric: string; node?: string };
type Window = { label: string; comparison: Schemas["StorePhaseComparison"] };

export function ActivationPhaseComparison({ net, dataset, onAuth }: { net: number; dataset: number; onAuth: () => void }) {
  const captures = useLoad(async () => (await get("/v1/networks/{net}/datasets", { path: { net }, query: { kind: "observations" } })).datasets.filter((d) => d.status === "complete"), [net]);
  const [captureID, setCaptureID] = useState(0), [key, setKey] = useState("");
  const capture = useLoad(async () => captureID ? get("/v1/networks/{net}/datasets/{dataset}/observations", { path: { net, dataset: captureID } }) : null, [net, captureID]);
  const declaration = capture.state === "done" && capture.data?.dataset_id === captureID ? capture.data : null;
  const keys = declaration ? Object.keys(declaration.node.rule_activations).sort() : [];
  const [before, setBefore] = useState("50"), [after, setAfter] = useState("50");
  const [node, setNode] = useState(""), [metric, setMetric] = useState("round_to_decision");
  const [error, setError] = useState(""), [query, setQuery] = useState<Query | null>(null);
  const result = useLoad(async () => query ? get("/v1/networks/{net}/datasets/{dataset}/phases/activation", { path: { net, dataset }, query }) : null, [net, dataset, JSON.stringify(query)]);
  const data = query && result.state === "done" ? result.data : null;
  const [source, setSource] = useState<{ dataset: number; ordinal: number } | null>(null);
  const original = useLoad(async () => source ? get("/v1/networks/{net}/datasets/{dataset}/observations/calls/{ordinal}", { path: { net, ...source } }) : null, [net, source?.dataset, source?.ordinal]);
  const windows: Window[] = data ? [...(data.before ? [{ label: "Before", comparison: data.before }] : []), { label: "At or after", comparison: data.after }] : [];
  const chartRuns = windows.flatMap(({ label, comparison }) => comparison.runs.map((run) => ({ ...run, name: label })));
  const hasChart = chartRuns.some((run) => run.summary.groups.some((group) => group.valid > 0));
  return <details className="activation-phase-comparison"><summary>Compare phases around a reported rule activation</summary>
    <p>Compare this run before and at or after a rule activation height reported by a completed node capture on the same chain and genesis. The declaration is a recorded node claim. It does not prove that run observers used the rule or that a measured difference was caused by it.</p>
    <Pending load={captures} onAuth={onAuth} />
    <form onSubmit={(event) => {
      event.preventDefault();
      if (!declaration || !Object.hasOwn(declaration.node.rule_activations, key)) { setError("Choose a rule explicitly reported by the selected capture."); return; }
      try { activationWindows(declaration.node.rule_activations[key]!, before, after); } catch (failure) { setError((failure as Error).message); return; }
      setError(""); setSource(null); setQuery({ capture: captureID, key, before: Number(before), after: Number(after), metric, ...(node ? { node } : {}) });
    }}>
      <div className="controls"><label>Activation declaration capture <select value={captureID} onChange={(event) => { setCaptureID(Number(event.target.value)); setKey(""); setQuery(null); setSource(null); setError(""); }}><option value={0}>Choose a completed capture</option>{captures.state === "done" && captures.data.map((d) => <option key={d.id} value={d.id}>{d.name} (capture {d.id})</option>)}</select></label>
        <label>Reported rule <select value={key} onChange={(event) => { setKey(event.target.value); setQuery(null); setSource(null); setError(""); }}><option value="">Choose a reported rule</option>{keys.map((value) => <option key={value}>{value}</option>)}</select></label>
        <label>Heights before activation <input value={before} inputMode="numeric" onChange={(event) => setBefore(event.target.value)} /></label>
        <label>Heights at or after activation <input value={after} inputMode="numeric" onChange={(event) => setAfter(event.target.value)} /></label>
        <label>Activation comparison observer <input value={node} onChange={(event) => setNode(event.target.value)} placeholder="All run observers" /></label>
        <label>Activation comparison metric <select value={metric} onChange={(event) => setMetric(event.target.value)}>{metrics.map((value) => <option key={value}>{value}</option>)}</select></label>
        <button disabled={!declaration || !keys.includes(key)}>Compare activation windows</button></div>
      {declaration && keys.length === 0 && <p>This capture reports no activation declarations. An absent declaration is not a disabled rule.</p>}
      {declaration && keys.includes(key) && <p>Selected declaration: {key} from full height {declaration.node.rule_activations[key]}. The earlier window stops one height before it; the later window includes it.</p>}
      {error && <p role="alert">{error}</p>}
    </form>
    {captureID > 0 && <Pending load={capture} onAuth={onAuth} />}
    {query && <Pending load={result} onAuth={onAuth} />}
    {data && <section className="activation-results" key={JSON.stringify(query)}>
      <h3>{data.key}: reported from {data.from} · {data.metric}</h3>
      <p>Capture {data.capture.dataset_id} ({data.capture_name}) · declaring node <code>{data.capture.node.address}</code>. The capture node is not inferred to be a run observer. Before and after statistics keep observers, profiles and clocks separate.</p>
      {!data.before && <p>No earlier height interval exists because the reported activation height is zero.</p>}
      <p>{data.context_records} phase and engine-boundary records read across both windows. Missing and negative measurements are not zero latency.</p>
      <ol className="activation-intervals" aria-label="Activation comparison intervals">{windows.map(({ label, comparison }) => <li key={label}><strong>{label}</strong><br />Full heights {comparison.rounds.from}–{comparison.rounds.to}<br />{comparison.rounds.expected_heights} heights</li>)}</ol>
      <p className="muted">On narrow screens, scroll charts and tables sideways to read full labels and values.</p>
      <div className="activation-charts" tabIndex={hasChart ? 0 : undefined} role={hasChart ? "region" : undefined} aria-label={hasChart ? "Activation percentile charts" : undefined}><PhaseComparisonBands runs={chartRuns} /></div>
      <div className="table-scroll" tabIndex={0} role="region" aria-label="Activation phase distribution table"><table aria-label="Activation window phase distributions"><thead><tr><th>Window / observer / profile / clock</th><th>Total / valid</th><th>Missing / negative / invalid clock</th><th>p50 / p95 / p99</th><th>Mean / stddev</th></tr></thead><tbody>{windows.flatMap(({ label, comparison }) => comparison.runs.flatMap((run) => run.summary.groups.map((group) => <tr key={`${label}:${group.node}:${group.profile}:${group.clock}`}><th>{label} / {group.node} / {group.profile} / {group.clock}</th><td>{group.total} / {group.valid}</td><td>{group.missing} / {group.negative} / {group.invalid_clock}</td><td>{seconds(group.p50_seconds)} / {seconds(group.p95_seconds)} / {seconds(group.p99_seconds)}</td><td>{seconds(group.mean_seconds)} / {seconds(group.stddev_seconds)}</td></tr>)))}</tbody></table></div>
      <h3>Height coverage and recorded round claims</h3><p>Phase attempts and observer head claims are different evidence. An unobserved height does not establish a failed network decision.</p>
      <div className="table-scroll" tabIndex={0} role="region" aria-label="Activation height coverage table"><table aria-label="Activation window coverage"><thead><tr><th>Window / full-height range / observer / profile</th><th>Phase heights / unobserved</th><th>Known / unknown / missing round claims</th><th>Round counts</th></tr></thead><tbody>{windows.flatMap(({ label, comparison }) => comparison.runs.flatMap((run) => run.coverage.map((coverage) => {
        const observer = comparison.rounds.runs[0]?.observers.find((candidate) => candidate.node === coverage.node && candidate.profile === coverage.profile);
        return <tr key={`${label}:${coverage.node}:${coverage.profile}`}><th>{label} {comparison.rounds.from}–{comparison.rounds.to} / {coverage.node} / {coverage.profile}</th><td>{coverage.observed_heights} / {coverage.unobserved_heights}</td><td>{observer ? `${observer.known} / ${observer.unknown} / ${observer.missing}` : "unavailable"}</td><td>{observer?.bins.map((bin) => `${bin.round}: ${bin.count}`).join("; ") || "none"}</td></tr>;
      })))}</tbody></table></div>
      <details><summary>Original activation declaration and source identity</summary>
        <p style={{ overflowWrap: "anywhere" }}>Chain {data.capture.node.chain_id} · genesis <code>{data.capture.node.genesis_hash}</code> · recorded head {data.capture.node.head_number}.</p>
        <p style={{ overflowWrap: "anywhere" }}>Source {data.capture.source_kind} · SHA256 <code>{data.capture.source_sha256}</code> · snapshot <code>{data.capture.snapshot}</code>.</p>
        <p style={{ overflowWrap: "anywhere" }}>Reported rules digest <code>{data.capture.node.rules_digest}</code>.</p>
        <button type="button" onClick={() => setSource({ dataset: data.capture.dataset_id, ordinal: data.declaration_call })}>Open original activation request {data.declaration_call}</button>
      </details>
      {windows.map((window) => <ActivationWindowEvidence key={window.label} net={net} window={window} />)}
    </section>}
    {source && <aside><h3>Original activation declaration request {source.ordinal}</h3><Pending load={original} onAuth={onAuth} />{original.state === "done" && original.data && <><p>{original.data.method} · {original.data.status} · capture {source.dataset} · envelope SHA256 {original.data.sha256}.</p><pre>{JSON.stringify(original.data, null, 2)}</pre></>}</aside>}
  </details>;
}

function ActivationWindowEvidence({ net, window: { label, comparison } }: { net: number; window: Window }) {
  const run = comparison.runs[0];
  if (!run) return null;
  return <details><summary>{label}: input hashes and original measurements</summary>
    <p>Full heights {comparison.rounds.from}–{comparison.rounds.to}. Examples show the first node/profile/clock/status measurement, up to 64 for this window. {run.examples_truncated ? "Additional examples are omitted; all measurements remain in the statistics and coverage." : "No example groups were omitted."}</p>
    {comparison.rounds.runs[0]?.inputs.map((input) => <p key={input.id} style={{ overflowWrap: "anywhere" }}>Input {input.id} · {input.node} / {input.profile} · SHA256 <code>{input.sha256}</code>.</p>)}
    <div className="table-scroll" tabIndex={0} role="region" aria-label={`${label} original phase measurements`}><table aria-label={`${label} activation phase evidence`}><thead><tr><th>Observer / profile</th><th>Full height / round</th><th>Clock / status / measurement</th><th>Original start / end</th></tr></thead><tbody>{run.examples.map((sample) => <tr key={sample.id}><th>{sample.node} / {sample.profile}</th><td>{sample.height} / {sample.round}</td><td>{sample.clock} / {sample.status} / {seconds(sample.seconds)}</td><td>{[sample.start, sample.end].map((source, index) => {
      const href = source ? phaseEvidenceLink(net, run.dataset, source.input, source.line) : undefined;
      return <span key={index}>{index === 0 ? "start " : "end "}{source ? href ? <a href={href}>{source.input}:{source.line}</a> : `${source.input}:${source.line}` : "missing"} </span>;
    })}</td></tr>)}</tbody></table></div>
  </details>;
}
