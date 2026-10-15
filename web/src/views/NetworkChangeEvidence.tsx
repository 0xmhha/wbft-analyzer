import {MembershipEvidence} from "./MembershipEvidence";
import { useState } from "react";
import type { Schemas } from "../api/client";
import { NodeLifecycleEvidence } from "./NodeLifecycleEvidence";
import {TimingChangeEvidence} from "./TimingChangeEvidence";
import {RecordedMessageEffect} from "./RecordedMessageEffect";
export function NetworkChangeEvidence({change,effect,timing,messages,membership,net,dataset,onAuth}:{change:Schemas["ScenarioNetworkChange"];effect?:Schemas["ScenarioLifecycleEffect"]|null;timing?:Schemas["ScenarioTimingEffect"]|null;messages?:Schemas["ScenarioMessageEffect"]|null;membership?:Schemas["ScenarioMembershipEffect"]|null;net?:number;dataset?:number;onAuth?:()=>void}){
 const [page,setPage]=useState(0),size=100;
 if(change.kind==="synthetic_membership")return <MembershipEvidence change={change} effect={membership}/>;
 if(change.kind==="node_lifecycle")return <NodeLifecycleEvidence change={change} effect={effect}/>;
 if(change.kind==="set_timing")return <TimingChangeEvidence change={change} effect={timing}/>;
 if(change.kind==="drop_message"||change.kind==="swap_messages")return <RecordedMessageEffect change={change} effect={messages} net={net} dataset={dataset} onAuth={onAuth}/>;
 const edges=change.kind==="cut_outgoing"?[]:change.edges,last=Math.max(0,Math.ceil(edges.length/size)-1),current=Math.min(page,last),start=current*size;
 const description=change.kind==="cut_outgoing"?`cut outgoing links from recorded node ${change.node}`:change.kind==="partition"?"explicit directed partition":change.kind==="set_link_delay"?`set link delay to ${change.delay_ns} ns for the whole registered run`:`scale link delays by ${change.scale.numerator}/${change.scale.denominator} for the whole registered run`;
 return <section aria-label="Counterfactual network intervention"><p>Counterfactual: {description}, {change.from_ns}–{change.to_ns} ns. Reverse links remain unchanged unless explicitly selected.</p>{change.kind==="scale_link_delay"&&<p>Exact rational scaling rounds down to integer nanoseconds per sample. Loss probabilities are unchanged.</p>}{change.kind==="set_link_delay"&&<p>Sample cardinality and loss probabilities are unchanged.</p>}{change.kind!=="cut_outgoing"&&<details><summary>Directed links ({edges.length})</summary><p role="status">Showing {edges.length?start+1:0}–{Math.min(start+size,edges.length)} of {edges.length} directions.</p><table><thead><tr><th>Recorded sender index</th><th>Recorded receiver index</th></tr></thead><tbody>{edges.slice(start,start+size).map(e=><tr key={`${e.from}:${e.to}`}><td>{e.from}</td><td>{e.to}</td></tr>)}</tbody></table><button disabled={current===0} onClick={()=>setPage(0)}>First directed links</button><button disabled={current===0} onClick={()=>setPage(current-1)}>Previous directed links</button><button disabled={current===last} onClick={()=>setPage(current+1)}>Next directed links</button><button disabled={current===last} onClick={()=>setPage(last)}>Last directed links</button></details>}</section>;
}
