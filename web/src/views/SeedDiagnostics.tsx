import type {Schemas} from "../api/client";
type Seed=Schemas["ScenarioSeedResult"];

export function SeedDiagnostics({mode,rows,expected}:{mode:string;rows:Seed[];expected:number}){
 return <section aria-label={`${mode} seed diagnostics`}><details><summary>{mode} seed diagnostics ({rows.length}/{expected} saved)</summary>
  <p>Simulator outcomes are separate from recorded observations and baseline distribution checks. Addresses below belong to simulated test keys.</p>
  {rows.length===0?<p>No seed outcomes retained yet.</p>:<table><thead><tr><th>Seed / status</th><th>Compared heights</th><th>Simulated elapsed ns</th><th>Violations and execution details</th></tr></thead><tbody>{rows.map(r=><tr key={r.seed}><td>{r.seed} · {r.status}</td><td>{r.heights.length} saved · {r.heights[0]?.number??"unavailable"}–{r.heights.at(-1)?.number??"unavailable"}</td><td>{r.simulation_ns}</td><td>{r.violations} violations<details><summary>Execution details for seed {r.seed}</summary>{r.execution?<>
   <p>Configured stop height: {r.execution.configured_stop_height==="0"?"unspecified":r.execution.configured_stop_height} · configured duration ns: {r.execution.configured_duration_ns==="0"?"unspecified":r.execution.configured_duration_ns}</p>
   <table><thead><tr><th>Node index</th><th>Simulated address</th><th>Last head</th></tr></thead><tbody>{r.execution.nodes.map(n=><tr key={n.index}><td>{n.index}</td><td>{n.simulated_address||"unavailable"}</td><td>{n.head}</td></tr>)}</tbody></table>
   {r.execution.violations.length!==r.violations&&<p role="alert">Stored violation count and details disagree.</p>}
   {r.execution.violations.length===0?<p>{r.violations===0?"No simulator violations reported in this execution record.":"Violation details are unavailable or inconsistent."}</p>:<ul>{r.execution.violations.map((v,i)=><li key={i}><strong>{v.kind}</strong> · simulated node {v.simulated_node}<p>{v.detail}</p></li>)}</ul>}
  </>:<p>Execution details were not retained for this historical seed. Violation kinds and final node heads are unavailable; counts do not establish a cause.</p>}</details></td></tr>)}</tbody></table>}
 </details></section>;
}
