import type { Schemas } from "./api/client";
export type TimingFields={timeout:string;period:string;cap:string;nodes:string};
type Values=Schemas["ScenarioTimingValues"];
export function timingChange(fields:TimingFields,nodes:number,duration:number):Extract<Schemas["ScenarioNetworkChange"],{kind:"set_timing"}>{
 if(!Number.isSafeInteger(duration)||duration<=0||duration>86400000000000||!Number.isInteger(nodes)||nodes<2||nodes>256)throw new Error("Invalid registered timing scope.");
 const maximum=(9223372036854775807n-BigInt(duration))/1000000000n;
 function values(timeout:string,period:string,cap:string):Values{
  const out:Values={};
  for(const [key,raw,zero] of [["request_timeout_seconds",timeout,false],["block_period_seconds",period,false],["max_request_timeout_seconds",cap,true]] as const){
   if(raw==="")continue;
   if(!/^(0|[1-9][0-9]*)$/.test(raw)||BigInt(raw)>maximum||(!zero&&raw==="0"))throw new Error(`Use integer seconds up to ${maximum}; timeout and period must be positive. A zero maximum removes the cap.`);
   out[key]=raw;
  }
  return out;
 }
 const global=values(fields.timeout,fields.period,fields.cap),overrides:Schemas["ScenarioNodeTimingChange"][]=[],seen=new Set<number>();
 for(const line of fields.nodes.split(/\r?\n/).filter(x=>x.trim()!=="")){
  const m=/^\s*(0|[1-9][0-9]*)\s+(\S+)\s+(\S+)\s+(\S+)\s*$/.exec(line);
  if(!m)throw new Error("Enter node index, timeout seconds, block-period seconds and maximum seconds per line. Use - to inherit a field.");
  const node=Number(m[1]);
  if(!Number.isSafeInteger(node)||node>=nodes||seen.has(node))throw new Error("Use each recorded node index at most once.");
  const parsed=values(...m.slice(2).map(x=>x==="-"?"":x) as [string,string,string]);
  if(Object.keys(parsed).length===0)throw new Error("Each node row must explicitly change at least one timing field.");
  seen.add(node);overrides.push({node,values:parsed});
  if(overrides.length>256)throw new Error("Use at most 256 node overrides.");
 }
 if(Object.keys(global).length===0&&overrides.length===0)throw new Error("Enter at least one global or per-node timing value.");
 overrides.sort((a,b)=>a.node-b.node);
 return {kind:"set_timing",from_ns:0,to_ns:duration,timing:{...(Object.keys(global).length?{global}:{}),...(overrides.length?{nodes:overrides}:{})}};
}
