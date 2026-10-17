import {useState} from "react";
import type {Schemas} from "../api/client";
import {get} from "../api/client";
import {Pending,useLoad} from "../ui";

type Record=Schemas["MessagesRecord"];
type Point=Schemas["MessagesOwnSourcePoint"];
type Focus="header"|"footer";
const format="wbft-sync-notifications/1";
const flag=(value:boolean|null|undefined)=>value===true?"yes":value===false?"no":"unknown";
const samePoint=(a:Point|null|undefined,b:Point|null|undefined)=>!!a&&!!b&&a.input===b.input&&a.file===b.file&&a.ordinal===b.ordinal&&a.seq===""&&b.seq==="";

export function getTypedSyncSource(net:number,dataset:number,point:Point){
 return get("/v1/networks/{net}/datasets/{dataset}/messages/source",{path:{net,dataset},query:{input:point.input,file:point.file,ordinal:String(point.ordinal)}});
}

export function matchesTypedSyncSource(parent:Record,source:Record,focus:Focus){
 const proof=parent.sync_notification_evidence,original=source.sync_notification_evidence;
 const point=focus==="header"?proof?.header:proof?.footer;
 const metadata=source.sync_notification_source;
 if(!proof||!original||typeof proof.retained_complete!=="boolean"||original.retained_complete!==proof.retained_complete||proof.header.ordinal!==1||!point||point.seq!==""||point.ordinal<1||source.input!==point.input||source.file!==point.file||source.ordinal!==point.ordinal||source.seq!==""||source.node!==parent.node||source.run!==parent.run||source.type!=="sync_notification_source"||metadata?.format!==format||metadata.stage!==focus||!samePoint(proof.header,original.header))return false;
 if(!!proof.footer!==!!original.footer||proof.footer&&!samePoint(proof.footer,original.footer))return false;
 if(focus==="header")return !metadata.footer&&metadata.header?.format===format&&metadata.header.type==="header"&&metadata.header.node===parent.node&&metadata.header.run===parent.run&&metadata.header.core_start_seq==="0"&&typeof metadata.header.validator==="boolean";
 return !metadata.header&&metadata.footer?.type==="footer"&&typeof metadata.footer.complete==="boolean"&&typeof metadata.footer.core_complete==="boolean"&&typeof metadata.footer.closed_normally==="boolean";
}

export function SyncNotificationEvidence({net,dataset,record,onAuth}:{net:number;dataset:number;record:Record;onAuth:()=>void}){
 const [focus,setFocus]=useState<Focus|null>(null);
 const notification=record.sync_notification,metadata=record.sync_notification_source,proof=record.sync_notification_evidence;
 const point=focus==="header"?proof?.header:focus==="footer"?proof?.footer:null;
 const load=useLoad(async()=>point?getTypedSyncSource(net,dataset,point):null,[net,dataset,point?.input,point?.file,point?.ordinal]);
 if(!notification&&!metadata)return null;
 const original=load.state==="done"?load.data:null;
 const matches=!!original&&!!focus&&matchesTypedSyncSource(record,original,focus);
 const header=metadata?.header,footer=metadata?.footer;
 return <section className="sync-evidence" aria-label="Typed downloader notifications">
  <h3>Typed downloader notifications</h3>
  <p>These are the original downloader notifications. A complete source file does not prove consensus correctness or who produced it.</p>
  {notification&&<>
   <p>Downloader {notification.kind} notification · original notification sequence <code>{notification.sequence}</code> · source row {record.ordinal}.</p>
   <p>Posting clock: {notification.posted_at_available?notification.posted_at||"unavailable":"unavailable"}. This is separate from journal positions and consensus event sequences; no monotonic clock was recorded.</p>
   {notification.kind==="done"&&<><p>Reported downloaded block number <code>{notification.number||"unavailable"}</code></p><p className="mono">Reported downloaded header hash {notification.hash||"unavailable"}</p><p>Matching a completion to canonical blocks requires a separate source comparison.</p></>}
  </>}
  {header&&<><p>Original process header · validator: {flag(header.validator)}.</p><p>Reported core start seq <code>{header.core_start_seq}</code>. This header has no original notification sequence.</p></>}
  {footer&&<>
   <p>Original source footer · observed {footer.observed} · written {footer.written} · dropped {footer.dropped} · invalid {footer.invalid}.</p>
   <p>Producer reports complete: {flag(footer.complete)} · normal shutdown: {flag(footer.closed_normally)} · core lifecycle coverage claimed: {flag(footer.core_complete)} · sequence exhausted: {flag(footer.sequence_exhausted)}.</p>
   <p>Reported core stop seq <code>{footer.core_stop_seq||"unavailable"}</code>. This footer has no original notification sequence.</p>
  </>}
  <p>Recording node <code>{record.node}</code> · process <code>{record.run}</code>.</p>
  {proof&&<p>{proof.retained_complete?"Complete retained file":"Incomplete retained file"}. {proof.footer?"Original footer retained.":"Original footer unavailable."} File coverage is separate from the producer's claims and a consensus-policy verdict.</p>}
  <div className="controls">{proof&&<button type="button" aria-pressed={focus==="header"} onClick={()=>setFocus("header")}>Open original notification header</button>}{proof?.footer&&<button type="button" aria-pressed={focus==="footer"} onClick={()=>setFocus("footer")}>Open original notification footer</button>}</div>
  {point&&<aside key={`${focus}:${point.input}:${point.file}:${point.ordinal}`} className="sync-original" aria-label="Original typed notification source"><h4>{focus} source: {point.file}:{point.ordinal}</h4><Pending load={load} onAuth={onAuth}/>{original&&<><p className={matches?undefined:"error"}>{matches?"Original metadata matches the retained file pointer.":"Original metadata does not match this file pointer."}</p><pre>{JSON.stringify(original,null,2)}</pre></>}</aside>}
 </section>;
}
