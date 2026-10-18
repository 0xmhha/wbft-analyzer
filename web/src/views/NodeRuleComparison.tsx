import { useEffect, useState } from "react";
import { get, type Schemas } from "../api/client";
import { compareNodeRules, declaredActivation, fullHeight } from "../nodeRules";
import { Pending, useLoad } from "../ui";

function abbreviated(value: string): string {
  return value.length > 26 ? `${value.slice(0, 12)}…${value.slice(-8)}` : value;
}

export function NodeRuleComparison({ net, datasets, onAuth, onCapture }: {
  net: number;
  datasets: Schemas["StoreDataset"][];
  onAuth: () => void;
  onCapture: (dataset: number) => void;
}) {
  const [chosen, setChosen] = useState<number[]>([]);
  const [height, setHeight] = useState("");
  const [error, setError] = useState("");
  const [query, setQuery] = useState<{ captures: { id: number; name: string }[]; height: string } | null>(null);
  useEffect(() => { setChosen([]); setQuery(null); setHeight(""); setError(""); }, [net]);
  const load = useLoad(async () => {
    if (!query) return null;
    const captures = await Promise.all(query.captures.map(async ({ id, name }) => ({
      ...await get("/v1/networks/{net}/datasets/{dataset}/observations", { path: { net, dataset: id } }), name,
    })));
    return { captures, comparison: compareNodeRules(captures) };
  }, [net, JSON.stringify(query)]);
  const available = datasets.filter((dataset) => dataset.kind === "observations" && dataset.status === "complete");
  const data = load.state === "done" ? load.data : null;
  return <details className="node-rule-comparison"><summary>Compare node rules and activation heights</summary>
    <p>Select 2–16 completed captures from this network. Digests and activation declarations are recorded node claims. Captures have independent recorded heads and are not simultaneous observations; a difference does not independently establish a fork or a conformance failure.</p>
    {available.length < 2 ? <p>At least two completed node observation captures are needed.</p> : <form onSubmit={(event) => {
      event.preventDefault();
      try { if (height !== "") fullHeight(height); } catch { setError("Use a canonical nonnegative full height, or leave it empty."); return; }
      const selected = chosen.flatMap((id) => {
        const dataset = available.find((candidate) => candidate.id === id);
        return dataset ? [{ id, name: dataset.name }] : [];
      });
      if (selected.length !== chosen.length) { setError("Choose completed captures from the current network."); return; }
      setError("");
      setQuery({ captures: selected, height });
    }}>
      <fieldset><legend>Node configuration captures</legend><div className="controls">{available.map((dataset) => <label key={dataset.id}>
        <input type="checkbox" checked={chosen.includes(dataset.id)} onChange={(event) => setChosen(event.target.checked ? [...chosen, dataset.id] : chosen.filter((id) => id !== dataset.id))} />
        {dataset.name} (capture {dataset.id})
      </label>)}</div></fieldset>
      <div className="controls"><label>Inspect declarations at full height (optional) <input inputMode="numeric" value={height} onChange={(event) => setHeight(event.target.value)} /></label>
        <button disabled={chosen.length < 2 || chosen.length > 16}>Compare node configurations</button></div>
      <p>{chosen.length} selected / maximum 16.</p>{error && <p role="alert">{error}</p>}
    </form>}
    <Pending load={load} onAuth={onAuth} />
    {data && <>
      <h3>{data.comparison.digestAgreement === "different" ? "Different reported rules digests" : data.comparison.digestAgreement === "matching" ? "Matching reported rules digests" : "Incomplete reported rules digests"}</h3>
      <p>{data.captures.length} captures · {data.comparison.distinctNodes} distinct recorded node addresses. Matching digests are metadata agreement, not independent verification of applied rules.</p>
      {data.comparison.repeatedNodes.length > 0 && <p>Repeated node snapshots: {data.comparison.repeatedNodes.join(", ")}. Their differences do not by themselves establish disagreement between distinct nodes.</p>}
      <ul aria-label="Reported digest groups">{data.comparison.digestGroups.map((group, index) => <li key={group.digest}>Digest group {index + 1} · {group.datasets.length} {group.datasets.length === 1 ? "capture" : "captures"}: {group.datasets.map((id) => `capture ${id}`).join(", ")}.</li>)}</ul>
      <div className="table-scroll"><table aria-label="Recorded node rule digest comparison"><thead><tr><th>Capture</th><th>Node / implementation / profile</th><th>Recorded head</th><th>Reported rules digest</th><th>Original evidence</th></tr></thead><tbody>
        {data.captures.map((capture, index) => <tr key={capture.dataset_id}>
          <th>{capture.name} (capture {capture.dataset_id})</th><td><details><summary>{abbreviated(capture.node.address)}</summary><code>{capture.node.address}</code></details>{capture.node.impl} / {capture.node.log_profile}</td>
          <td>{capture.node.head_number}<details><summary>Hash {abbreviated(capture.node.head_hash)}</summary><code>{capture.node.head_hash}</code></details></td><td>{data.comparison.digests[index] ? <><strong>Digest group {data.comparison.digestGroups.findIndex((group) => group.digest === data.comparison.digests[index]) + 1}</strong><details><summary>{abbreviated(data.comparison.digests[index])}</summary><code>{data.comparison.digests[index]}</code></details></> : "unavailable or malformed"}</td>
          <td><button type="button" onClick={() => onCapture(capture.dataset_id)}>Open capture {capture.dataset_id}</button><details><summary>Source identity</summary><p>Source {capture.source_sha256} · snapshot {capture.snapshot}.</p>
            {capture.calls.filter((call) => call.method === "wbft_nodeInfo").map((call) => <p key={call.ordinal}>Original node request {call.ordinal} · {call.status} · {call.sha256}.</p>)}</details></td>
        </tr>)}
      </tbody></table></div>
      <h3>Reported activation declarations</h3><p>An absent declaration is not a disabled rule. Height zero is a reported activation height.{query?.height ? ` The labels at full height ${query.height} evaluate only each reported schedule, not historical execution.` : ""}</p>
      {data.comparison.rules.length === 0 ? <p>No activation declarations were reported in these captures.</p> : <div className="table-scroll"><table aria-label="Recorded activation height comparison"><thead><tr><th>Rule / declaration comparison</th>{data.captures.map((capture) => <th key={capture.dataset_id}>{capture.name} (capture {capture.dataset_id})</th>)}</tr></thead><tbody>
        {data.comparison.rules.map((rule) => <tr key={rule.key}><th>{rule.key} / {rule.agreement}</th>{rule.heights.map((from, index) => <td key={data.captures[index]!.dataset_id}>{from === null ? "not declared" : `from ${from}`}{query?.height && from !== null && <><br />{declaredActivation(from, query.height)}</>}</td>)}</tr>)}
      </tbody></table></div>}
    </>}
  </details>;
}
