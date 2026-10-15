import type { Schemas } from "./api/client";
type Change=Schemas["ScenarioNetworkChange"];
export type ChangeKind=Change["kind"];
export type DelayFields={nanoseconds?:string;numerator?:string;denominator?:string;lifecycle?:string;schedulePolicy?:string};
/** Recorded node indices keep their direction; no reverse edges are inferred. */
export function networkChange(kind:ChangeKind,node:number,text:string,from:string,to:string,nodes:number,duration:number,delay:DelayFields={}):Change{
 const a=Number(from),b=Number(to);
 if(!/^(0|[1-9][0-9]*)$/.test(from)||!/^[1-9][0-9]*$/.test(to)||!Number.isSafeInteger(a)||!Number.isSafeInteger(b)||a<0||b<=a||b>duration||nodes<2||nodes>256)throw new Error("Choose a cut interval inside the registered duration.");
 if(kind==="cut_outgoing"){
  if(!Number.isInteger(node)||node<0||node>=nodes)throw new Error("Choose a recorded node.");
  return {kind,node,from_ns:a,to_ns:b};
 }
 if(kind==="node_lifecycle"){
  const schedule_policy=delay.schedulePolicy;
  if(schedule_policy!=="merge"&&schedule_policy!=="replace_window")throw new Error("Choose how to combine recorded node commands.");
  const lifecycle:{node:number;at_ns:number;action:"stop"|"restart"}[]=[],seen=new Set<string>();
  for(const line of (delay.lifecycle??"").split(/\r?\n/).filter(line=>line.trim()!=="")){
   const m=/^\s*(0|[1-9][0-9]*)\s+(stop|restart)\s+(0|[1-9][0-9]*)\s*$/.exec(line);
   if(!m)throw new Error("Enter node index, stop or restart, and nanoseconds per line.");
   const node=Number(m[1]),at_ns=Number(m[3]);
   if(!Number.isSafeInteger(node)||node>=nodes||!Number.isSafeInteger(at_ns)||at_ns<a||at_ns>b)throw new Error("Each node command must lie inside the model and inclusive command window.");
   const key=`${node}:${at_ns}`;if(seen.has(key))throw new Error("Use only one command per node at each nanosecond.");seen.add(key);
   lifecycle.push({node,at_ns,action:m[2] as "stop"|"restart"});if(lifecycle.length>4096)throw new Error("Use at most 4096 node commands.");
  }
  if(lifecycle.length===0)throw new Error("Choose at least one node command.");
  lifecycle.sort((x,y)=>x.at_ns-y.at_ns||x.node-y.node);
  return {kind,from_ns:a,to_ns:b,lifecycle,schedule_policy};
 }
 if(kind!=="partition"&&kind!=="set_link_delay"&&kind!=="scale_link_delay")throw new Error("Unsupported network change.");
 if(kind!=="partition"&&(a!==0||b!==duration))throw new Error("Link delay changes apply to the whole registered run.");
 const edges: {from:number;to:number}[]=[],seen=new Set<string>();
 for(const line of text.split(/\r?\n/).filter(line=>line.trim()!=="")){
  const m=/^\s*(0|[1-9][0-9]*)\s*->\s*(0|[1-9][0-9]*)\s*$/.exec(line);
  if(!m)throw new Error("Enter one directed link per line, for example 0 -> 1.");
  const from=Number(m[1]),to=Number(m[2]);
  if(!Number.isSafeInteger(from)||!Number.isSafeInteger(to)||from>=nodes||to>=nodes||from===to)throw new Error("Each link must join two different recorded node indices.");
  const key=`${from}:${to}`;if(seen.has(key))throw new Error("Remove duplicate directed links.");seen.add(key);edges.push({from,to});
  if(edges.length>nodes*(nodes-1))throw new Error("Too many directed links for this model.");
 }
 if(edges.length===0)throw new Error("Choose at least one directed link.");
 edges.sort((a,b)=>a.from-b.from||a.to-b.to);
 if(kind==="partition")return {kind,from_ns:a,to_ns:b,edges};
 if(kind==="set_link_delay"){
  const raw=delay.nanoseconds??"",value=Number(raw);
  if(!/^(0|[1-9][0-9]*)$/.test(raw)||!Number.isSafeInteger(value)||value<0||value>86400000000000)throw new Error("Choose an exact delay from 0 to 86400000000000 nanoseconds.");
  return {kind,from_ns:a,to_ns:b,edges,delay_ns:value};
 }
 const n=delay.numerator??"",d=delay.denominator??"",maximum=18446744073709551615n;
 if(!/^(0|[1-9][0-9]*)$/.test(n)||!/^[1-9][0-9]*$/.test(d)||BigInt(n)>maximum||BigInt(d)>maximum)throw new Error("Use unsigned integer ratio terms up to 18446744073709551615 and a positive denominator.");
 let numerator=BigInt(n),denominator=BigInt(d),aRatio=numerator,bRatio=denominator;
 while(bRatio!==0n){[aRatio,bRatio]=[bRatio,aRatio%bRatio]}
 numerator/=aRatio;denominator/=aRatio;
 return {kind,from_ns:a,to_ns:b,edges,scale:{numerator:numerator.toString(),denominator:denominator.toString()}};
}

export function allDirectedLinks(nodes:number):string{
 if(!Number.isInteger(nodes)||nodes<2||nodes>256)throw new Error("Invalid registered node count.");
 const lines:string[]=[];for(let from=0;from<nodes;from++)for(let to=0;to<nodes;to++)if(from!==to)lines.push(`${from} -> ${to}`);
 return lines.join("\n");
}
