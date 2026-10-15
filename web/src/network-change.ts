import type { Schemas } from "./api/client";
type Change=Schemas["ScenarioNetworkChange"];
/** Recorded node indices keep their direction; no reverse edges are inferred. */
export function networkChange(kind:"cut_outgoing"|"partition",node:number,text:string,from:string,to:string,nodes:number,duration:number):Change{
 const a=Number(from),b=Number(to);
 if(!/^(0|[1-9][0-9]*)$/.test(from)||!/^[1-9][0-9]*$/.test(to)||!Number.isSafeInteger(a)||!Number.isSafeInteger(b)||a<0||b<=a||b>duration||nodes<2||nodes>256)throw new Error("Choose a cut interval inside the registered duration.");
 if(kind==="cut_outgoing"){
  if(!Number.isInteger(node)||node<0||node>=nodes)throw new Error("Choose a recorded node.");
  return {kind,node,from_ns:a,to_ns:b};
 }
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
 return {kind,from_ns:a,to_ns:b,edges};
}
