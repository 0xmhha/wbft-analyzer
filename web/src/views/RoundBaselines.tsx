import { useState } from "react";
import { get } from "../api/client";
import type { Schemas } from "../api/client";
import { Pending,useLoad } from "../ui";
export function RoundBaselines({net,datasets,onAuth}:{net:number;datasets:Schemas["StoreDataset"][];onAuth:()=>void}){
 const [chosen,setChosen]=useState<number[]>([]),[from,setFrom]=useState("6"),[to,setTo]=useState("55"),[node,setNode]=useState("");
 const [query,setQuery]=useState<{datasets:string;from:string;to:string;node?:string}|null>(null);
 const load=useLoad(async()=>query?get("/v1/networks/{net}/rounds/baseline",{path:{net},query}):null,[net,JSON.stringify(query)]);
 return <details><summary>Compare independent run round baselines</summary><p>Compare the same full-height range of 2–16 completed runs. Reused node/profile/source hashes are rejected. Each observer stays separate; these claims do not pool into network decisions. Rates use known claims, and missing/unknown counts remain visible. Equal run weights and sample variance describe these runs, not a universal acceptance threshold.</p>
 <form onSubmit={(e)=>{e.preventDefault();setQuery({datasets:chosen.join(","),from,to,...(node?{node}:{})})}}>
 <div className="controls">{datasets.filter((d)=>d.status==="complete").map((d)=><label key={d.id}><input type="checkbox" checked={chosen.includes(d.id)} onChange={(e)=>setChosen(e.target.checked?[...chosen,d.id]:chosen.filter((id)=>id!==d.id))}/>{d.name}</label>)}</div>
 <div className="controls"><label>Baseline first full height <input inputMode="numeric" value={from} onChange={(e)=>setFrom(e.target.value)}/></label><label>Baseline last full height <input inputMode="numeric" value={to} onChange={(e)=>setTo(e.target.value)}/></label><label>Baseline observer node <input value={node} onChange={(e)=>setNode(e.target.value)} placeholder="All observers"/></label><button disabled={chosen.length<2||chosen.length>16}>Compare run baselines</button></div></form>
 <Pending load={load} onAuth={onAuth}/>{load.state==="done"&&load.data&&<><p>{load.data.expected_heights} expected heights per observer/run · {load.data.method}</p>
 <div className="table-scroll"><table><thead><tr><th>Run / node / profile</th><th>Known / unknown / missing</th><th>Recorded round counts</th></tr></thead><tbody>{load.data.runs.flatMap((r)=>r.observers.map((o)=><tr key={`${r.dataset}:${o.node}:${o.profile}`}><td>{r.name} / {o.node} / {o.profile}</td><td>{o.known} / {o.unknown} / {o.missing}</td><td>{o.bins.map((b)=>`${b.round}: ${b.count}`).join("; ")||"none"}</td></tr>))}</tbody></table></div>
 <div className="table-scroll"><table><thead><tr><th>Observer / profile / round</th><th>Valid run samples</th><th>Mean fraction</th><th>Sample variance / stddev</th><th>Each run: count / denominator</th></tr></thead><tbody>{load.data.comparisons.map((c)=><tr key={`${c.node}:${c.profile}:${c.round}`}><td>{c.node} / {c.profile} / {c.round}</td><td>{c.runs}</td><td>{c.mean_fraction===null?"unknown":c.mean_fraction.toFixed(6)}</td><td>{c.sample_variance===null?"unknown":c.sample_variance.toFixed(8)} / {c.sample_stddev===null?"unknown":c.sample_stddev.toFixed(6)}</td><td>{c.samples.map((r)=>`${r.dataset}: ${r.count}/${r.denominator}${r.fraction===null?" (unavailable)":""}`).join("; ")}</td></tr>)}</tbody></table></div>
 <details><summary>Baseline source hashes</summary>{load.data.runs.map((r)=><p key={r.dataset}>{r.name}: {r.inputs.map((i)=>`${i.node}/${i.profile} ${i.sha256}`).join("; ")}</p>)}</details></>}
 </details>
}
