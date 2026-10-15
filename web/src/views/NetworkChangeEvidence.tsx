import type { Schemas } from "../api/client";
export function NetworkChangeEvidence({change}:{change:Schemas["ScenarioNetworkChange"]}){
 return <section aria-label="Counterfactual network intervention"><p>Counterfactual: {change.kind==="cut_outgoing"?`cut outgoing links from recorded node ${change.node}`:"explicit directed partition"}, {change.from_ns}–{change.to_ns} ns. Reverse links remain unchanged unless explicitly selected.</p>{change.kind==="partition"&&<details><summary>Directed links ({change.edges.length})</summary><table><thead><tr><th>Recorded sender index</th><th>Recorded receiver index</th></tr></thead><tbody>{change.edges.map(e=><tr key={`${e.from}:${e.to}`}><td>{e.from}</td><td>{e.to}</td></tr>)}</tbody></table></details>}</section>;
}
