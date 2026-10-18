import { useState } from "react";
import { get, type Schemas } from "../api/client";
import { phaseEvidenceLink, phaseHeightRange } from "../phaseComparison";
import { Pending, useLoad } from "../ui";
import { seconds } from "./PhaseLatency";

const metrics = ["preprepare", "prepare_quorum", "commit_quorum", "commit", "import", "round_to_decision", "round_to_import"];
type Run = Schemas["StorePhaseComparisonRun"];

export function RunPhaseComparison({ net, datasets, onAuth, onRun }: {
  net: number; datasets: Schemas["StoreDataset"][]; onAuth: () => void; onRun: (dataset: number) => void;
}) {
  const [chosen, setChosen] = useState<number[]>([]);
  const [from, setFrom] = useState("6"), [to, setTo] = useState("55");
  const [node, setNode] = useState(""), [metric, setMetric] = useState("round_to_decision");
  const [error, setError] = useState("");
  const [independentNetworks, setIndependentNetworks] = useState(false);
  const [query, setQuery] = useState<{ datasets: string; from: string; to: string; node?: string; metric: string; cross_network?: string } | null>(null);
  const load = useLoad(async () => query ? get("/v1/networks/{net}/phases/comparison", { path: { net }, query }) : null, [net, JSON.stringify(query)]);
  const data = query && load.state === "done" ? load.data : null;
  const otherRuns = useLoad(async () => {
    if (!independentNetworks) return [];
    const { networks } = await get("/v1/networks");
    const runs: Schemas["StoreDataset"][] = [];
    for (const network of networks) {
      if (network.id === net) continue;
      const result = await get("/v1/networks/{net}/datasets", { path: { net: network.id }, query: { kind: "run" } });
      runs.push(...result.datasets);
    }
    return runs;
  }, [net, independentNetworks]);
  const available = [...datasets, ...(independentNetworks && otherRuns.state === "done" ? otherRuns.data : [])].filter((run) => run.kind === "run" && run.status === "complete");
  return <details className="run-phase-comparison"><summary>Compare run phases and round distributions</summary>
    <p>Compare 2–16 completed runs over the same full-height interval. Independent runs do not share wall-clock windows. Each run, observer, profile and clock stays separate; missing or negative measurements are not zero latency. Independent networks retain their chain and genesis identities. These measurements do not establish a conformance verdict or a causal improvement.</p>
    <label><input type="checkbox" checked={independentNetworks} onChange={(event) => {
      const enabled = event.target.checked;
      setIndependentNetworks(enabled);
      setChosen((ids) => enabled ? ids : ids.filter((id) => datasets.some((run) => run.id === id && run.kind === "run" && run.status === "complete")));
      setQuery(null); setError("");
    }} />Include runs from independent networks</label>
    <Pending load={otherRuns} onAuth={onAuth} />
    <form onSubmit={(event) => {
      event.preventDefault();
      try { phaseHeightRange(from, to); } catch (failure) { setError((failure as Error).message); return; }
      if (chosen.some((id) => !available.some((run) => run.id === id))) { setError("Choose completed runs from the selected network scope."); return; }
      setError(""); setQuery({ datasets: chosen.join(","), from, to, metric, ...(node ? { node } : {}), ...(independentNetworks ? { cross_network: "1" } : {}) });
    }}>
      <fieldset><legend>Phase comparison runs</legend><div className="controls">{available.map((run) => <label key={run.id}>
        <input type="checkbox" checked={chosen.includes(run.id)} onChange={(event) => setChosen(event.target.checked ? [...chosen, run.id] : chosen.filter((id) => id !== run.id))} />{run.name} (network {run.network_id}, run {run.id})
      </label>)}</div></fieldset>
      <div className="controls"><label>Comparison first full height <input value={from} inputMode="numeric" onChange={(event) => setFrom(event.target.value)} /></label>
        <label>Comparison last full height <input value={to} inputMode="numeric" onChange={(event) => setTo(event.target.value)} /></label>
        <label>Comparison observer <input value={node} onChange={(event) => setNode(event.target.value)} placeholder="All observers" /></label>
        <label>Comparison phase metric <select value={metric} onChange={(event) => setMetric(event.target.value)}>{metrics.map((value) => <option key={value}>{value}</option>)}</select></label>
        <button disabled={chosen.length < 2 || chosen.length > 16}>Compare run phases</button></div>
      <p>{chosen.length} selected / maximum 16. At most 100000 heights and 100000 relevant context records across the selection.</p>
      {error && <p role="alert">{error}</p>}
    </form>
    <Pending load={load} onAuth={onAuth} />
    {data && <>
      <h3>{data.metric} · full heights {data.rounds.from}–{data.rounds.to}</h3>
      {new Set(data.runs.map((run) => run.network.genesis_hash)).size > 1 && <p>These runs have different genesis hashes. The shared numeric interval does not identify the same chain state.</p>}
      <p>{data.context_records} relevant context records. {data.method}</p>
      <PhaseComparisonBands runs={data.runs} />
      <div className="table-scroll"><table aria-label="Independent run phase distributions"><thead><tr><th>Run / node / profile / clock</th><th>Total / valid</th><th>Missing / negative / invalid clock</th><th>p50</th><th>p95</th><th>p99</th><th>Mean / stddev</th></tr></thead><tbody>
        {data.runs.flatMap((run) => run.summary.groups.map((group) => <tr key={`${run.dataset}:${group.node}:${group.profile}:${group.clock}`}><th>{run.name} (network {run.network.id}, run {run.dataset}) / {group.node} / {group.profile} / {group.clock}</th><td>{group.total} / {group.valid}</td><td>{group.missing} / {group.negative} / {group.invalid_clock}</td><td>{seconds(group.p50_seconds)}</td><td>{seconds(group.p95_seconds)}</td><td>{seconds(group.p99_seconds)}</td><td>{seconds(group.mean_seconds)} / {seconds(group.stddev_seconds)}</td></tr>))}
      </tbody></table></div>
      <h3>Phase observation coverage</h3><p>An unobserved height has no phase attempt in these inputs. It does not establish that the network failed to decide. Missing phase endpoints are counted separately above.</p>
      <div className="table-scroll"><table aria-label="Phase comparison height coverage"><thead><tr><th>Run / node / profile</th><th>Heights with attempts</th><th>Unobserved heights</th></tr></thead><tbody>{data.runs.flatMap((run) => run.coverage.map((coverage) => <tr key={`${run.dataset}:${coverage.node}:${coverage.profile}`}><th>{run.name} (network {run.network.id}) / {coverage.node} / {coverage.profile}</th><td>{coverage.observed_heights}</td><td>{coverage.unobserved_heights}</td></tr>))}</tbody></table></div>
      <h3>Recorded round distributions</h3><p>Round counts are deduplicated observer head claims over the same {data.rounds.expected_heights} heights. Unknown and absent head claims remain separate from phase coverage.</p>
      <div className="table-scroll"><table aria-label="Phase comparison round distributions"><thead><tr><th>Run / node / profile</th><th>Known / unknown / missing</th><th>Round counts</th></tr></thead><tbody>{data.rounds.runs.flatMap((run) => run.observers.map((observer) => <tr key={`${run.dataset}:${observer.node}:${observer.profile}`}><th>{run.name} (network {data.runs.find((phase) => phase.dataset === run.dataset)?.network.id}) / {observer.node} / {observer.profile}</th><td>{observer.known} / {observer.unknown} / {observer.missing}</td><td>{observer.bins.map((bin) => `${bin.round}: ${bin.count}`).join("; ") || "none"}</td></tr>))}</tbody></table></div>
      {data.runs.map((run) => <details key={run.dataset}><summary>{run.name}: source identity and example measurements</summary>
        <p style={{ overflowWrap: "anywhere" }}>Network {run.network.id} · chain {run.network.chain_id} · genesis <code>{run.network.genesis_hash}</code>.</p>
        {run.network.id === net && <button type="button" onClick={() => onRun(run.dataset)}>Open run {run.dataset}</button>}
        <p>Original links retain the source view. Decision records can carry their number and round as explicit fields when that view is unavailable.</p>
        <p>Examples show the first measurement of each node/profile/clock/status, up to 64 per run. {run.examples_truncated ? "Additional examples are omitted; full statistics and coverage above still include all selected measurements." : "No example groups were omitted."}</p>
        {data.rounds.runs.find((round) => round.dataset === run.dataset)?.inputs.map((input) => <p key={input.id} style={{ overflowWrap: "anywhere" }}>Input {input.id} · {input.node} / {input.profile} · SHA256 <code>{input.sha256}</code></p>)}
        <div className="table-scroll"><table aria-label={`Run ${run.dataset} phase evidence examples`}><thead><tr><th>Node / profile</th><th>Full height / round</th><th>Clock / status / measurement</th><th>Start / end original event</th></tr></thead><tbody>{run.examples.map((sample) => <tr key={sample.id}><th>{sample.node} / {sample.profile}</th><td>{sample.height} / {sample.round}</td><td>{sample.clock} / {sample.status} / {seconds(sample.seconds)}</td><td>{[sample.start, sample.end].map((source, index) => {
          const href = source ? phaseEvidenceLink(run.network.id, run.dataset, source.input, source.line) : undefined;
          return source ? <span key={index}>{index === 0 ? "start " : "end "}{href ? <a href={href}>{source.input}:{source.line}</a> : `${source.input}:${source.line}`} </span> : <span key={index}>{index === 0 ? "start" : "end"} missing </span>;
        })}</td></tr>)}</tbody></table></div>
      </details>)}
    </>}
  </details>;
}

function PhaseComparisonBands({ runs }: { runs: Run[] }) {
  return <>{["monotonic", "wall"].map((clock) => {
    const all = runs.flatMap((run) => run.summary.groups.filter((group) => group.clock === clock && group.p50_seconds !== null && group.p95_seconds !== null && group.p99_seconds !== null).map((group) => ({ run, group })));
    if (!all.length) return null;
    const rows = all.slice(0, 32), maximum = all.reduce((max, { group }) => Math.max(max, group.p99_seconds ?? 0), .000001);
    const x = (value: number) => 280 + 490 * value / maximum;
    return <figure key={clock}><figcaption>{clock}: p50 marker, bar through p95, p99 endpoint · common scale. {all.length > rows.length ? `Showing the first ${rows.length} of ${all.length} groups; all groups remain in the table.` : `${rows.length} measured groups.`}</figcaption>
      <svg viewBox={`0 0 800 ${45 + rows.length * 30}`} role="img" aria-label={`Independent run phase percentile comparison ${clock}`}>
        <text x="280" y="15">0 ms</text><text x="680" y="15">{seconds(maximum)}</text>
        {rows.map(({ run, group }, index) => { const label = `${run.name} (net ${run.network.id}) / ${group.node} / ${group.profile}`; return <g key={`${run.dataset}:${group.node}:${group.profile}`}><title>{`${label}: p50 ${seconds(group.p50_seconds)}, p95 ${seconds(group.p95_seconds)}, p99 ${seconds(group.p99_seconds)}; ${group.valid} valid`}</title>
          <text x="0" y={39 + index * 30} fontSize="10">{label.length > 45 ? label.slice(0, 42) + "…" : label}</text>
          <rect x="280" y={25 + index * 30} width={x(group.p95_seconds!) - 280} height="18" fill="#7954c7" opacity=".45" />
          <line x1={x(group.p50_seconds!)} x2={x(group.p50_seconds!)} y1={23 + index * 30} y2={45 + index * 30} stroke="#3a2870" strokeWidth="3" />
          <circle cx={x(group.p99_seconds!)} cy={34 + index * 30} r="4" fill="#3a2870" />
        </g>; })}
      </svg>
    </figure>;
  })}</>;
}
