import type {Schemas} from "./api/client";

export type SyntheticNodeFields={alias:string;start:string;timeout:string;period:string;cap:string;build:string;imports:string};
type Change=Schemas["ScenarioNetworkChange"];

function integer(raw:string,max:bigint,label:string,positive=false):string{
 const value=raw.trim();
 if(!/^(0|[1-9][0-9]*)$/.test(value)||BigInt(value)>max||positive&&BigInt(value)===0n)throw new Error(`Enter ${label} as an exact ${positive?"positive":"nonnegative"} integer up to ${max}.`);
 return value;
}
function samples(text:string,max:bigint,label:string){
 const values=text.split(",");if(values.length===0||values.length>256)throw new Error(`Use 1–256 ${label} samples.`);
 return values.map(raw=>({ns:integer(raw,max,label)}));
}

/** New node indices append to recorded indices; no recorded key is reassigned. */
export function membershipChange(original:number,duration:number,policy:string,nodes:SyntheticNodeFields[],linkText:string,epochText:string):Change{
 if(!Number.isInteger(original)||original<2||original+nodes.length>256||!Number.isSafeInteger(duration)||duration<=0||duration>86400000000000)throw new Error("Choose a bounded registered model with at most 256 total nodes.");
 if(policy!=="merge"&&policy!=="replace_from_first_epoch")throw new Error("Choose how to combine epoch schedules.");
 const aliases=new Set<string>();
 const synthetic=nodes.map(n=>{
  if(!/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/.test(n.alias)||aliases.has(n.alias))throw new Error("Use unique node aliases of 1–64 letters, digits, underscores or hyphens.");
  aliases.add(n.alias);
  const start_ns=integer(n.start,BigInt(duration-1),"startup nanoseconds"),maxSeconds=(9223372036854775807n-BigInt(duration))/1000000000n;
  return {alias:n.alias,model:"unmeasured_compat" as const,start_ns,timing:{request_timeout_seconds:integer(n.timeout,maxSeconds,"request timeout seconds",true),block_period_seconds:integer(n.period,maxSeconds,"block period seconds",true),max_request_timeout_seconds:integer(n.cap,maxSeconds,"maximum request timeout seconds")},build_delay:samples(n.build,3600000000000n,"build delay nanoseconds"),import_delay:samples(n.imports,3600000000000n,"import delay nanoseconds")};
 });
 const total=original+nodes.length,links:Schemas["ScenarioMembershipLink"][]=[],edges=new Set<string>();
 for(const line of linkText.split(/\r?\n/).filter(l=>l.trim()!=="")){
  const match=/^\s*(0|[1-9][0-9]*)\s*->\s*(0|[1-9][0-9]*)\s*\|\s*([^|]+)\|\s*([^|]+)\s*$/.exec(line);
  if(!match)throw new Error("Enter each new directed link as from -> to | delay samples ns | loss ppm.");
  const from=Number(match[1]),to=Number(match[2]),key=`${from}:${to}`;
  if(!Number.isInteger(from)||!Number.isInteger(to)||from>=total||to>=total||from===to||from<original&&to<original||edges.has(key))throw new Error("List each direction touching a synthetic node exactly once; recorded links are preserved.");
  edges.add(key);links.push({from,to,delays:samples(match[3]!,86400000000000n,"link delay nanoseconds"),loss_ppm:integer(match[4]!,999999n,"loss parts per million")});
 }
 if(links.length!==total*(total-1)-original*(original-1))throw new Error("Supply every direction between a synthetic node and every other node.");
 links.sort((a,b)=>a.from-b.from||a.to-b.to);
 const epochs:Schemas["ScenarioMembershipEpoch"][]=[],blocks=new Set<string>(),used=new Set<number>();
 for(const line of epochText.split(/\r?\n/).filter(l=>l.trim()!=="")){
  const match=/^\s*([0-9]+)\s*:\s*(.+)\s*$/.exec(line);
  if(!match)throw new Error("Enter each epoch as block: candidate indices separated by commas.");
  const block=integer(match[1]!,10000n,"epoch block",true),candidates=match[2]!.split(",").map(raw=>Number(integer(raw,BigInt(total-1),"candidate index")));
  if(blocks.has(block)||candidates.length===0||candidates.length>256||new Set(candidates).size!==candidates.length)throw new Error("Use distinct epoch blocks and distinct candidate indices in each epoch.");
  blocks.add(block);candidates.forEach(n=>used.add(n));epochs.push({block,candidates});
  if(epochs.length>10000)throw new Error("Use at most 10000 epoch changes.");
 }
 if(epochs.length===0)throw new Error("Supply at least one epoch candidate change.");
 for(let n=original;n<total;n++)if(!used.has(n))throw new Error("Every synthetic node must be requested as a candidate in at least one epoch.");
 epochs.sort((a,b)=>Number(a.block)-Number(b.block));
 return {kind:"synthetic_membership",from_ns:0,to_ns:duration,membership:{policy,nodes:synthetic,links,epochs}};
}
