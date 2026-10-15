import type { Schemas } from "../api/client";

type Probability = Schemas["ScenarioConditionalProbability"];
type Timing = Schemas["ScenarioHeaderTimeComparison"];

function ProbabilityEvidence({label,value}:{label:string;value:Probability|null}){
 if(!value)return <p>{label}: unavailable</p>;
 return <div><h4>{label}</h4><p>Method: {value.method}<br/>p: {value.p==null?"unavailable":value.underflow?"below floating-point range":String(value.p)}{value.log_p!=null&&<> · log(p): {value.log_p}</>}<br/>{value.exact?"Exact conditional enumeration or analytic result":"Monte Carlo conditional estimate"} · {value.samples} tables or label assignments</p>
  {!value.exact&&<p>Numerical tail-probability bounds: [{value.lower}, {value.upper}] · error probability ≤ {value.error_probability} · random seed {value.seed}. These bounds describe computation error, not physical timing uncertainty.</p>}
  {value.issue&&<p>Unavailable evidence: {value.issue}</p>}
 </div>;
}

export function ScenarioTimeEvidence({timing,check}:{timing?:Timing|null;check:string}){
 if(!timing)return <section aria-label="Header interval baseline"><h3>Header interval baseline</h3><p>{check==="pending"?"Time distribution check pending.":"Time distribution criteria unavailable for this stored experiment."}</p></section>;
 return <section className={`scenario-comparison ${check==="passed"?"":"scenario-unproved"}`} aria-label="Header interval baseline">
  <h3>Header interval baseline: {check}</h3><p>Distribution result: {timing.status} · significance level α = {timing.alpha}<br/>Criterion: {timing.method}<br/>Heights {timing.from}–{timing.to} · {timing.recorded_runs} recorded runs · {timing.simulated_runs} baseline seeds</p>
  {timing.issue&&<p>Acceptance unavailable: {timing.issue}</p>}
  <p>Maximum empirical CDF difference: {timing.maximum_cdf_difference}. Every integer-second interval category is retained. Non-rejection does not establish exact timing equality or physical equivalence.</p>
  <ProbabilityEvidence label="Recorded run homogeneity" value={timing.recorded_homogeneity}/>
  <ProbabilityEvidence label="Baseline seed homogeneity" value={timing.simulated_homogeneity}/>
  <ProbabilityEvidence label="Recorded versus baseline intervals" value={timing.comparison}/>
  <p>Combined numerical error probability bound: {timing.numerical_error_probability}</p>
  <details><summary>Complete interval histograms</summary>{[...timing.recorded,...timing.simulated].map(run=><div key={run.run}><h4>{run.run}{run.seed&&` · seed ${run.seed}`} · {run.samples} heights</h4><table><thead><tr><th>Interval seconds</th><th>Height count</th></tr></thead><tbody>{run.counts.map(c=><tr key={c.seconds}><td>{c.seconds}</td><td>{c.count}</td></tr>)}</tbody></table></div>)}</details>
  <details><summary>Time comparison assumptions</summary><ul>{timing.assumptions.map(a=><li key={a}>{a.replaceAll("_"," ")}</li>)}</ul></details>
 </section>;
}
