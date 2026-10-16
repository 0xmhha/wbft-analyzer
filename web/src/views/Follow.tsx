import { useEffect, useState } from "react";
import { get, type Schemas } from "../api/client";
import { Pending, useLoad } from "../ui";

export function Follow({net,onAuth}:{net:number;onAuth:()=>void}) {
 const [refresh,setRefresh]=useState(0),[auto,setAuto]=useState(true);
 useEffect(()=>{if(!auto)return;const timer=setInterval(()=>setRefresh(n=>n+1),5000);return()=>clearInterval(timer)},[auto]);
 const runs=useLoad(async()=>(await get("/v1/networks/{net}/datasets",{path:{net},query:{kind:"follow"}})).datasets,[net,refresh]);
 return <section><h1>Native follow progress</h1><p>Each source retains its own next canonical index. A participation gap or unavailable RPC keeps that position for retry. Stored progress does not imply complete event or message capture.</p><div className="controls"><label><input type="checkbox" checked={auto} onChange={e=>setAuto(e.target.checked)}/>Refresh every 5 seconds</label><button type="button" onClick={()=>setRefresh(n=>n+1)}>Refresh progress</button></div><Pending load={runs} onAuth={onAuth}/>{runs.state==="done"&&(runs.data.length?runs.data.map(d=><FollowSource key={d.id} net={net} dataset={d.id} name={d.name} refresh={refresh} onAuth={onAuth}/>):<p>No follow source yet.</p>)}</section>;
}
function FollowSource({net,dataset,name,refresh,onAuth}:{net:number;dataset:number;name:string;refresh:number;onAuth:()=>void}) {
 const load=useLoad(()=>get("/v1/networks/{net}/datasets/{dataset}/follow",{path:{net,dataset}}),[net,dataset,refresh]);
 return <article><h2>{name}</h2><Pending load={load} onAuth={onAuth}/>{load.state==="done"&&<FollowProgress state={load.data}/>}</article>;
}
export function FollowProgress({state}:{state:Schemas["StoreFollowState"]}) {
 return <><p>{state.captured_heights.toLocaleString()} committed heights · next canonical index <strong className="mono">{state.cursor.next_index}</strong> · stored status {state.status}</p>{state.last_issue&&<p className="error">Last collection issue: {state.last_issue}. The committed position is retained.</p>}<p>Last committed batch: {state.total_batches?state.last_commit_at:"none yet"}. A stored importing status alone does not confirm that the collector is still running.</p><details><summary>{state.total_batches} committed batches; latest {state.latest_batches.length} shown</summary><table><thead><tr><th>Canonical indices</th><th>Header dataset</th><th>Native observation dataset</th></tr></thead><tbody>{state.latest_batches.map(b=><tr key={b.from_index}><td className="mono">{b.from_index}–{b.to_index}</td><td>{b.headers_dataset}</td><td>{b.observations_dataset}</td></tr>)}</tbody></table><p className="mono">Last committed parent hash: {state.cursor.parent_hash}</p></details></>;
}
