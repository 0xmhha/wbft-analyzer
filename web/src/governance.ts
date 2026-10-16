import type {Schemas} from "./api/client";

export type Collection=Schemas["GovernancePage"]["collection"];
export type GovernanceOperation=Schemas["GovernanceOperation"];
export function governanceCollections(method:string):Collection[]{
 switch(method){
  case "wbft_govOps":return ["operations"];
  case "wbft_mirrorFaults":return ["faults"];
  case "wbft_mirrorState":return ["states"];
  case "wbft_govProposal":return ["proposals","operations"];
  case "wbft_validatorChanges":return ["changes","operations"];
  case "wbft_mirror":return ["mirrors"];
  default:return [];
 }
}
export function governanceIndex(value:string):string{
 return /^(0x0|0x[1-9a-f][0-9a-f]{0,15})$/.test(value)?`${BigInt(value)} (${value})`:"unknown";
}
export function governancePositions(values:string[]):number[]|null{
 if(values.some(v=>!/^(0x0|0x[1-9a-f][0-9a-f]{0,15})$/.test(v)))return null;
 if(!values.length)return [];
 const numbers=values.map(v=>BigInt(v));let low=numbers[0]!,high=low;
 for(const n of numbers){if(n<low)low=n;if(n>high)high=n;}
 // Only a bounded pixel coordinate crosses into Number, never a source index.
 return numbers.map(n=>high===low?420:60+Number((n-low)*720000n/(high-low))/1000);
}
export function governancePhase(signature:string):string{
 if(signature.startsWith("propose"))return "creation";
 if(/^(approve|disapprove)Proposal\(/.test(signature))return "vote";
 if(/^(executeProposal|executeWithFailure)\(/.test(signature))return "execution";
 if(/^(cancel|expire)Proposal\(/.test(signature))return "closure";
 if(/^(changeMember|configureValidator)\(/.test(signature))return "configuration";
 return "unknown";
}
export function governanceOutcome(op:Pick<GovernanceOperation,"result"|"effective"|"view">):{kind:string;label:string}{
 if(op.result==="revert")return {kind:"failed",label:"failed attempt"};
 if(op.result!=="success")return {kind:"unknown",label:"attempt · outcome unknown"};
 if(op.view)return {kind:"attempt",label:"view attempt"};
 return op.effective?{kind:"effective",label:"effective (reported)"}:{kind:"attempt",label:"attempt · not effective"};
}
export function governanceProposalStatus(status:number):string{
 return ["none","voting","approved","executed","cancelled","expired","failed","rejected"][status]??`unknown (${status})`;
}
export function governancePointer(value:unknown,pointer:string):unknown{
 if(pointer==="")return value;
 if(!pointer.startsWith("/"))return undefined;
 let next=value;
 for(const part of pointer.slice(1).split("/")){
  const key=part.replace(/~1/g,"/").replace(/~0/g,"~");
  if(next===null||typeof next!=="object"||!Object.prototype.hasOwnProperty.call(next,key))return undefined;
  next=(next as Record<string,unknown>)[key];
 }
 return next;
}
