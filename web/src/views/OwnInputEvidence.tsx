import { useState } from "react";
import { get } from "../api/client";
import type { Schemas } from "../api/client";
import { Pending, useLoad } from "../ui";

type Record = Schemas["MessagesRecord"];
type Point = Schemas["MessagesOwnSourcePoint"];
type Proof = Schemas["MessagesOwnInputEvidence"];

export function getOwnInputSource(net:number,dataset:number,point:Point) {
 return get("/v1/networks/{net}/datasets/{dataset}/messages/source",{path:{net,dataset},query:{input:point.input,file:point.file,ordinal:String(point.ordinal)}});
}

export function matchesOwnInputSource(parent:Record,source:Record,point:Point,proof:Proof) {
 return source.input===point.input && source.file===point.file && source.ordinal===point.ordinal && source.seq===point.seq && source.node===parent.node && source.run===parent.run && source.engine_run===proof.engine_run && source.step===proof.step && source.dedup_key===parent.dedup_key && source.phase===parent.phase && source.type===(point.seq===proof.input.seq?"own_input":"outcome");
}

export function OwnInputEvidence({net,dataset,record,onAuth}:{net:number;dataset:number;record:Record;onAuth:()=>void}) {
 const proof=record.own_input_evidence;
 const [focus,setFocus]=useState<Point|null>(null);
 const original=useLoad(async()=>focus?getOwnInputSource(net,dataset,focus):null,[net,dataset,focus]);
 if(!proof)return null;
 const matches=focus && original.state==="done" && original.data && matchesOwnInputSource(record,original.data,focus,proof);
 return <section className="own-input-evidence" aria-label="Accepted own-message provenance">
  <h3>Accepted own bytes</h3>
  <p>These source links connect the same signed bytes to an accepted internal input. Link order is independent of execution time. A wire write and delivery remain separate observations.</p>
  <ol className="own-proof-chain">
   <li><strong>Recorded bytes</strong><code>{record.payload_sha256||record.dedup_key}</code></li>
   <li><button type="button" onClick={()=>setFocus(proof.outcome)}>Open accepted outcome source</button><span>{proof.outcome.file}:{proof.outcome.ordinal} · original seq {proof.outcome.seq}</span></li>
   <li><button type="button" onClick={()=>setFocus(proof.input)}>Open internal input source</button><span>{proof.input.file}:{proof.input.ordinal} · original seq {proof.input.seq}</span></li>
  </ol>
  <p>Writer <code>{record.run}</code> · engine <code>{proof.engine_run}</code> · step <code>{proof.step}</code></p>
  <p>Original journal segment <code>{proof.journal_position.segment}</code> · byte <code>{proof.journal_position.offset}</code>. Authenticating this location requires the retained raw journal.</p>
  {focus&&<aside aria-label="Original own-message source"><h4>Original record {focus.input}:{focus.file}:{focus.ordinal}</h4><Pending load={original} onAuth={onAuth}/>{original.state==="done"&&original.data&&<><p className={matches?undefined:"error"}>{matches?"Original source coordinates, writer, engine, step and message identity match.":"Original metadata does not match the recorded source link."}</p><pre>{JSON.stringify(original.data,null,2)}</pre></>}</aside>}
 </section>;
}
