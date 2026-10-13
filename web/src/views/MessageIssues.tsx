import { useState } from "react";
import { get, type Schemas } from "../api/client";
import { eventSourceLink } from "../sourceLink";
import { Pending, useLoad } from "../ui";

type Filters = {node:string;reason:string;source_dataset:string};
const empty:Filters={node:"",reason:"",source_dataset:""};
export function MessageIssues({net,dataset,nodes,onAuth,onSource}:{net:number;dataset:number;nodes:string[];onAuth:()=>void;onSource:(s:Schemas["MessagesSource"])=>void}) {
 const [draft,edit]=useState(empty),[filter,apply]=useState(empty),[cursors,setCursors]=useState<string[]>([]);
 const query=Object.fromEntries(Object.entries(filter).filter(([,v])=>v));
 const scope=JSON.stringify({net,dataset,query}),cursor=cursors.at(-1);
 const load=useLoad(()=>get("/v1/networks/{net}/datasets/{dataset}/messages/issues",{path:{net,dataset},query:{...query,limit:100,...(cursor?{cursor}:{})}}),[scope,cursor]);
 const sources=load.state==="done"?[...new Set(load.data.index.coverage.map(c=>c.dataset_id||dataset))]:[dataset];
 return <details><summary>Unprojected observations and original sources</summary><p>These observations could not be projected, or were retained as alternate evidence. They are not proof of failed transmission. Source filters apply to this list; phase, latency and pair filters apply to the charts and pair table.</p>
  <form className="controls" onSubmit={e=>{e.preventDefault();apply(draft);setCursors([])}}>
   <label>Issue source node<select value={draft.node} onChange={e=>edit({...draft,node:e.target.value})}><option value="">All source nodes</option>{nodes.map(n=><option key={n}>{n}</option>)}</select></label>
   <label>Projection reason<input value={draft.reason} onChange={e=>edit({...draft,reason:e.target.value})} placeholder="All reasons"/></label>
   <label>Source dataset<select value={draft.source_dataset} onChange={e=>edit({...draft,source_dataset:e.target.value})}><option value="">All associated sources</option>{sources.map(n=><option key={n} value={n}>{n}</option>)}</select></label>
   <button>Apply source filters</button><button type="button" onClick={()=>{edit(empty);apply(empty);setCursors([])}}>Clear source filters</button>
  </form><Pending load={load} onAuth={onAuth}/>
  {load.state==="done"&&<><p>{load.data.issues.length} observations on this page / {load.data.total} matching source observations.</p><div className="table-scroll"><table><thead><tr><th>Reason</th><th>Recording node / run</th><th>Original source</th><th>Recorded time / evidence</th></tr></thead><tbody>{load.data.issues.map(({ordinal,issue})=>{const s=issue.source,link=eventSourceLink(net,s,dataset);return <tr key={ordinal}><td>{issue.reason}</td><td>{s.node} / {s.run}</td><td>{s.dataset_id||dataset} / {s.input}:{s.file?`${s.file}:`:""}{s.ordinal}</td><td>{s.t_wall||"unavailable"}<button type="button" onClick={()=>onSource(s)}>Inspect observation</button>{link&&<a href={link}>Open source in replay</a>}</td></tr>})}</tbody></table></div><div className="controls"><button type="button" disabled={!cursors.length} onClick={()=>setCursors(cursors.slice(0,-1))}>Previous observations</button><button type="button" disabled={!load.data.next} onClick={()=>{if(load.data.next)setCursors([...cursors,load.data.next])}}>Next observations</button></div></>}
 </details>;
}
