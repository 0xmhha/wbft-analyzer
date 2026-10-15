import { useState } from "react";
import type { Schemas } from "../api/client";
import { bandPath,ecdfPath,extent,medianPath } from "../scenario-chart";
type Plot=Schemas["ScenarioComparisonPlot"];
type Group=Schemas["ScenarioDistribution"];
type Series={name:string;css:string;data:Group};
type Domain=[string,string];
export function ScenarioComparison({plot}:{plot:Plot}){
 const [page,setPage]=useState(0);
 const groups=[{name:"Recorded",css:"scenario-recorded",data:plot.recorded},{name:"Baseline seeds",css:"scenario-baseline",data:plot.baseline},{name:"Counterfactual seeds",css:"scenario-changed",data:plot.counterfactual}];
 const complete=groups.filter(g=>g.data.status==="complete");
 const heights=complete[0]?.data.elapsed_seconds.map(b=>b.height)??[];
 const roundDomain=extent(complete.flatMap(g=>g.data.rounds.map(p=>p.value)));
 const periodDomain=extent(complete.flatMap(g=>g.data.period_seconds.map(p=>p.value)));
 const heightDomain=extent(complete.flatMap(g=>g.data.elapsed_seconds.map(b=>b.height)));
 const elapsedDomain=extent(["0",...complete.flatMap(g=>g.data.elapsed_seconds.map(b=>b.maximum))]);
 const panels=[{title:"Recorded and baseline",counterfactual:false,groups:groups.slice(0,2)},{title:"Counterfactual",counterfactual:true,groups:groups.slice(2)}];
 return <section className={`scenario-comparison ${plot.credibility==="baseline_reproduced"?"":"scenario-unproved"}`} aria-label="Network distribution comparison">
 <h3>Recorded and simulated network outcomes</h3><p>Heights {plot.from}–{plot.to}. Header timestamps have integer-second resolution. Each recorded height is one observation; simulated nodes are not counted as independent samples.</p>
 {plot.credibility!=="baseline_reproduced"&&<p className="error"><strong>Baseline not established:</strong> {plot.credibility}. Counterfactual curves are model outputs and cannot establish a real network prediction.</p>}
 <p>Counterfactual curves describe the fitted model under its recorded assumptions. Baseline non-rejection does not establish physical equivalence or a real network prediction.</p>
 <ul className="scenario-legend">{groups.map(g=><li key={g.name} className={g.css}>{g.name}: {g.data.saved_runs}/{g.data.expected_runs} runs saved · {g.data.complete_runs} complete · {g.data.samples} plotted height samples{g.data.status!=="complete"&&<> · unavailable: {g.data.issue}</>}</li>)}</ul>
 <p>Both panels use the same axes. Hatched results are counterfactual model outputs, including when the baseline is reproduced.</p>
 <div className="scenario-panels">{panels.map(panel=><section key={panel.title} className={`scenario-panel${panel.counterfactual?" scenario-counterfactual":""}`} aria-label={`${panel.title} distributions`}><h4>{panel.title}</h4>{panel.groups.filter(g=>g.data.status!=="complete").map(g=><p key={g.name}>{g.name} distribution unavailable: {g.data.issue||g.data.status}</p>)}{panel.groups.some(g=>g.data.status==="complete")?<><ECDF title="Decision round ECDF" domain={roundDomain} groups={panel.groups.filter(g=>g.data.status==="complete").map(g=>({...g,points:g.data.rounds}))}/><ECDF title="Per-height header interval ECDF (seconds)" domain={periodDomain} groups={panel.groups.filter(g=>g.data.status==="complete").map(g=>({...g,points:g.data.period_seconds}))}/><Bands groups={panel.groups.filter(g=>g.data.status==="complete")} x={heightDomain} y={elapsedDomain}/></>:<p>No complete distributions available.</p>}</section>)}</div>
 <p>Seed bands show the observed minimum, lower median and maximum across all expected complete seeds. They are descriptive ranges, not confidence intervals or a time acceptance threshold.</p>
 {heights.length>0&&<details><summary>Exact elapsed header-time values by height</summary><table><thead><tr><th>Height</th>{complete.map(g=><th key={g.name}>{g.name}: min / median / max seconds</th>)}</tr></thead><tbody>{heights.slice(page*50,(page+1)*50).map((h,i)=><tr key={h}><th>{h}</th>{complete.map(g=>{const b=g.data.elapsed_seconds[page*50+i]!;return <td key={g.name}>{b.minimum} / {b.median} / {b.maximum}</td>})}</tr>)}</tbody></table><button disabled={page===0} onClick={()=>setPage(p=>p-1)}>Previous heights</button><button disabled={(page+1)*50>=heights.length} onClick={()=>setPage(p=>p+1)}>Next heights</button></details>}
 </section>;
}
function ECDF({title,groups,domain}:{title:string;groups:{name:string;css:string;points:Schemas["ScenarioDistributionPoint"][]}[];domain:Domain}){
 return <figure><figcaption>{title}</figcaption><svg className="scenario-chart" viewBox="0 0 790 245" role="img" aria-label={title}><text x="0" y="25">1</text><text x="0" y="215">0</text><g transform="translate(45,20)"><path className="scenario-axis" d="M0,0V190H700"/>{groups.map(g=><path key={g.name} className={`scenario-curve ${g.css}`} d={ecdfPath(g.points,domain)}><title>{g.name}: {g.points.map(p=>`${p.value}: ${(p.cumulative*100).toFixed(2)}% (${p.count} samples)`).join("; ")}</title></path>)}</g><text x="45" y="237">{domain[0]}</text><text x="745" y="237" textAnchor="end">{domain[1]}</text></svg><details><summary>Exact ECDF values</summary>{groups.map(g=><ECDFValues key={g.name} name={g.name} points={g.points}/>)}</details></figure>;
}
function ECDFValues({name,points}:{name:string;points:Schemas["ScenarioDistributionPoint"][]}){
 const [page,setPage]=useState(0);
 return <div><h4>{name}</h4><table><thead><tr><th>Value</th><th>Samples at value</th><th>Cumulative fraction</th></tr></thead><tbody>{points.slice(page*50,(page+1)*50).map(p=><tr key={p.value}><td>{p.value}</td><td>{p.count}</td><td>{p.cumulative}</td></tr>)}</tbody></table><button disabled={!page} onClick={()=>setPage(p=>p-1)}>Previous values</button><button disabled={(page+1)*50>=points.length} onClick={()=>setPage(p=>p+1)}>Next values</button></div>;
}
function Bands({groups,x,y}:{groups:Series[];x:Domain;y:Domain}){
 return <figure><figcaption>Elapsed header time from the first compared height (seconds)</figcaption><svg className="scenario-chart" viewBox="0 0 790 245" role="img" aria-label="Elapsed header-time seed bands"><text x="0" y="25">{y[1]}</text><text x="0" y="215">0</text><g transform="translate(45,20)"><path className="scenario-axis" d="M0,0V190H700"/>{groups.map(g=><g key={g.name} className={g.css}><path className="scenario-band" d={bandPath(g.data.elapsed_seconds,x,y)}/><path className="scenario-curve" d={medianPath(g.data.elapsed_seconds,x,y)}><title>{g.name}: lower median elapsed seconds</title></path></g>)}</g><text x="45" y="237">Height {x[0]}</text><text x="745" y="237" textAnchor="end">Height {x[1]}</text></svg></figure>;
}
