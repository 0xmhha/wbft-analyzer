import { SeedStaticChainSettings } from "./StaticChainSettings";
import {SeedMembershipEvidence} from "./MembershipEvidence";
import type {Schemas} from "../api/client";
import {useState} from "react";
import {SeedTimingEvidence} from "./SeedTimingEvidence";
import {SeedMessageEvidence} from "./SeedMessageEvidence";
type Seed=Schemas["ScenarioSeedResult"];

function NodeStarts({observations}:{observations:Schemas["ScenarioSeedLifecycleObservations"]}){
 const [page,setPage]=useState(0),rows=observations.node_starts,size=100,last=Math.max(0,Math.ceil(rows.length/size)-1),current=Math.min(page,last),start=current*size;
 return <section aria-label="Simulator node start observations"><p>Official simulator NODE_START observations: {observations.source}. Requests are separate; commands after the simulation stops produce no synthetic start observation. WAL record counts describe the same simulated node storage.</p><p role="status">Showing {rows.length?start+1:0}–{Math.min(start+size,rows.length)} of {rows.length} node starts.</p><table><thead><tr><th>Node index</th><th>Observed start ns</th><th>Simulator run</th><th>Status</th><th>Recovered WAL records</th></tr></thead><tbody>{rows.slice(start,start+size).map((r,i)=><tr key={i}><td>{r.node}</td><td>{r.at_ns}</td><td>{r.run}</td><td>{r.status}</td><td>{r.wal_records??"unavailable"}</td></tr>)}</tbody></table><button disabled={current===0} onClick={()=>setPage(0)}>First node starts</button><button disabled={current===0} onClick={()=>setPage(current-1)}>Previous node starts</button><button disabled={current===last} onClick={()=>setPage(current+1)}>Next node starts</button><button disabled={current===last} onClick={()=>setPage(last)}>Last node starts</button></section>;
}

export function SeedDiagnostics({mode,rows,expected}:{mode:string;rows:Seed[];expected:number}){
 return <section aria-label={`${mode} seed diagnostics`}><details><summary>{mode} seed diagnostics ({rows.length}/{expected} saved)</summary>
  <p>Simulator outcomes are separate from recorded observations and baseline distribution checks. Addresses below belong to simulated test keys.</p>
  {rows.length===0?<p>No seed outcomes retained yet.</p>:<table><thead><tr><th>Seed / status</th><th>Compared heights</th><th>Simulated elapsed ns</th><th>Violations and execution details</th></tr></thead><tbody>{rows.map(r=><tr key={r.seed}><td>{r.seed} · {r.status}</td><td>{r.heights.length} saved · {r.heights[0]?.number??"unavailable"}–{r.heights.at(-1)?.number??"unavailable"}</td><td>{r.simulation_ns}</td><td>{r.violations} violations<details><summary>Execution details for seed {r.seed}</summary>{r.execution?<>
   <p>Configured stop height: {r.execution.configured_stop_height==="0"?"unspecified":r.execution.configured_stop_height} · configured duration ns: {r.execution.configured_duration_ns==="0"?"unspecified":r.execution.configured_duration_ns}</p>
   <table><thead><tr><th>Node index</th><th>Simulated address</th><th>Last head</th></tr></thead><tbody>{r.execution.nodes.map(n=><tr key={n.index}><td>{n.index}</td><td>{n.simulated_address||"unavailable"}</td><td>{n.head}</td></tr>)}</tbody></table>
   {r.execution.lifecycle_observations?<NodeStarts observations={r.execution.lifecycle_observations}/>:<p>Node-start observations were not retained for this seed.</p>}
   {r.execution.timing_observations?<SeedTimingEvidence observations={r.execution.timing_observations}/>:<p>Timing observations were not retained for this seed.</p>}
   <SeedStaticChainSettings observations={r.execution.static_configuration_observations}/>{r.execution.membership_observations&&<SeedMembershipEvidence observations={r.execution.membership_observations}/>}
   {r.execution.message_observations&&<SeedMessageEvidence observations={r.execution.message_observations}/>}
   {r.execution.violations.length!==r.violations&&<p role="alert">Stored violation count and details disagree.</p>}
   {r.execution.violations.length===0?<p>{r.violations===0?"No simulator violations reported in this execution record.":"Violation details are unavailable or inconsistent."}</p>:<ul>{r.execution.violations.map((v,i)=><li key={i}><strong>{v.kind}</strong> · simulated node {v.simulated_node}<p>{v.detail}</p></li>)}</ul>}
  </>:<p>Execution details were not retained for this historical seed. Violation kinds and final node heads are unavailable; counts do not establish a cause.</p>}</details></td></tr>)}</tbody></table>}
 </details></section>;
}
