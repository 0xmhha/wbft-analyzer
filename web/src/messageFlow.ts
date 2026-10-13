import type { Schemas } from "./api/client";
import { stampNs } from "./replay";
export type Pair= Schemas["MessagesPair"];
export type FlowMark={pair:Pair;send:bigint|null;receive:bigint|null;band:[bigint,bigint]|null;connected:boolean;animate:boolean};
function stamp(s:string|undefined):bigint|null {try{return s?stampNs(s):null}catch{return null}}
/** Recorded endpoints and uncertainty remain facts; interpolation adds no observation. */
export function flowMarks(pairs:Pair[],cut?:{dataset:number;input:string;line:number;at:bigint}):FlowMark[]{return pairs.map(pair=>{
 const visible=(s:Pair["send"])=>!cut || !s || (s.kind!=="event"&&s.kind!=="log") || (s.dataset_id||cut.dataset)!==cut.dataset || stamp(s.t_wall)!==cut.at || s.input<cut.input || s.input===cut.input&&s.ordinal<=cut.line;
 const send=visible(pair.send)?stamp(pair.send?.t_wall):null,receive=visible(pair.receive)?stamp(pair.receive?.t_wall):null;
 const connected=pair.send_candidates===1 && pair.receive_candidates===1 && pair.status!=="ambiguous" && send!==null && receive!==null;
 const band: [bigint,bigint]|null=send!==null && pair.clock==="ntp" && pair.lower_seconds!==null && pair.upper_seconds!==null ? [send+BigInt(Math.round(pair.lower_seconds*1e9)),send+BigInt(Math.round(pair.upper_seconds*1e9))]:null;
 return {pair,send,receive,band,connected,animate:connected && pair.status==="valid" && pair.strength==="link" && pair.metric==="link" && send!<=receive!};
})}
export function flowFraction(mark:FlowMark,at:bigint):number|null {
 if(!mark.animate || mark.send===null || mark.receive===null || at<mark.send || at>mark.receive)return null;
 if(mark.receive===mark.send)return null;
 return Number(at-mark.send)/Number(mark.receive-mark.send);
}
export function canonicalFlowNode(node:string):string{return /^0x[0-9a-fA-F]{40}$/.test(node)?node.toLowerCase():node}
