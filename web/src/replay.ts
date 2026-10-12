import type { Schemas } from "./api/client";
export type ReplayState = Schemas["ReplayState"];
export type Record = Schemas["StoreLogEvent"];
export type Window = Schemas["StoreReplayWindow"];
export function stampNs(value: string): bigint {
 const m=/^(.*T\d\d:\d\d:\d\d)(?:\.(\d+))?Z$/.exec(value);
 if(!m) throw new Error("Replay requires normalized UTC timestamps");
 return BigInt(Date.parse(`${m[1]}Z`))*1000000n+BigInt((m[2]||"").padEnd(9,"0"));
}
export function nsStamp(n: bigint): string {
 let sec=n/1000000000n,part=n%1000000000n;if(part<0){sec--;part+=1000000000n}
 return new Date(Number(sec)*1000).toISOString().replace(/\.\d{3}Z$/,`.${part.toString().padStart(9,"0")}Z`);
}
function text(value:unknown):string{return typeof value==="string"?value:""}
export function empty(node:string):ReplayState{return {node,run:"",profile:"",online:null,engine_active:null,view:null,cause:"",state:"",state_source:null,counters:{},timers:{},backlog:null,backlog_partial:false,last_head:"",head_kind:"",latest:null,unmatched_timer_events:0}}
function reset(s:ReplayState){s.view=null;s.state="";s.state_source=null;s.cause="";s.counters={};s.timers={};s.backlog=null;s.backlog_partial=true}
// This is a visual projection of recorded fields, identical to the server fold.
// It never computes consensus transitions or a quorum from received messages.
export function apply(s:ReplayState,e:Record):void{
 const f=(e.fields||{}) as {[key:string]:unknown},p={input:e.input,line:e.line,t_wall:e.t_wall};
 if(s.run&&s.run!==e.run){reset(s);s.online=null;s.engine_active=null;s.last_head="";s.head_kind=""}
 s.run=e.run;s.profile=e.profile;s.latest=p;
 const view=e.height?{seq:e.height,round:e.round}:null;
 switch(e.kind){
 case "NODE_START":reset(s);s.online=true;break;
 case "NODE_STOP":s.online=false;s.engine_active=false;reset(s);break;
 case "ENGINE_START":reset(s);s.engine_active=true;break;
 case "ENGINE_STOP":s.engine_active=false;reset(s);break;
 case "ROUND_ENTER":if(view){s.view=view;s.counters={};s.state="";s.state_source=null;s.cause=text(f.cause)}break;
 case "STATE":if(view&&(!s.view||view.seq!==s.view.seq||view.round!==s.view.round))break;{const state=text(f.to)||text(f["new.state"]);if(state){s.state=state;s.state_source=p}}break;
 case "QUORUM":if(view&&(!s.view||view.seq!==s.view.seq||view.round!==s.view.round))break;{const what=text(f.what),key=({PREPARE:"prepares.count",COMMIT:"commits.count",F_PLUS_ONE:"higherRoundChanges.count",ROUND_CHANGE:"currentRoundChanges.count"} as {[key:string]:string})[what];if(what)s.counters[what]={count:text(f.count)||text(f[key || ""]),quorum:text(f.quorum),source:p}}break;
 case "TIMER_ARM":{const kind=text(f.timer);if(kind)s.timers[kind]={kind,engine:text(f.engine_run),generation:text(f.gen),status:"armed",deadline_mono_ns:text(f.deadline_mono_ns),duration_ms:text(f.duration_ms),source:p,closed:null}}break;
 case "TIMER_CANCEL":case "TIMER_FIRE":{if(f.stale===true)break;const kind=text(f.timer),timer=s.timers[kind];if(!timer||(timer.generation&&timer.generation!==text(f.gen))||(timer.engine&&timer.engine!==text(f.engine_run))){s.unmatched_timer_events++;break}timer.status=e.kind==="TIMER_CANCEL"?"cancelled":"fired";timer.closed=p}break;
 case "BACKLOG":{const explicit=text(f.backlogs_size);if(/^\d+$/.test(explicit)&&Number.isSafeInteger(Number(explicit))){s.backlog=Number(explicit);s.backlog_partial=false;break}if(s.backlog===null){s.backlog=0;s.backlog_partial=true}switch(f.op){case "push":s.backlog++;break;case "pop":case "drop":if(s.backlog>0)s.backlog--;else s.backlog_partial=true}}break;
 case "NEW_HEAD":if(text(f.number)){s.last_head=text(f.number);s.head_kind=e.source==="event"||e.profile.startsWith("wbft@")?"imported_head":"decision_claim"}break;
 }
}
export class Projection {
 readonly times: bigint[];
 readonly frames: {index:number;states:{[node:string]:ReplayState}}[]=[];
 constructor(readonly window:Window){
  this.times=window.events.map((e)=>stampNs(e.t_wall));const states:{[node:string]:ReplayState}={};for(const n of window.nodes)states[n.node]=structuredClone(n.initial.state);
  this.frames.push({index:0,states:structuredClone(states)});
  window.events.forEach((e,i)=>{states[e.node]??=empty(e.node);apply(states[e.node]!,e);if((i+1)%1024===0)this.frames.push({index:i+1,states:structuredClone(states)})});
 }
 indexAt(t:bigint):number{let lo=0,hi=this.times.length;while(lo<hi){const m=(lo+hi)>>1;if(this.times[m]!<=t)lo=m+1;else hi=m}return lo}
 seek(index:number):{[node:string]:ReplayState}{index=Math.max(0,Math.min(index,this.times.length));const frame=this.frames[Math.floor(index/1024)]||this.frames[0]!;const states=structuredClone(frame.states);for(let i=frame.index;i<index;i++){const e=this.window.events[i]!;states[e.node]??=empty(e.node);apply(states[e.node]!,e)}return states}
}
export type Cue={quorum:Record;message:Record|null;confidence:"step"|"inferred"|"unknown"};
export function quorumCues(events:Record[]):Cue[]{
 const byStep=new Map<string,Record[]>(),last=new Map<string,Record>();const out:Cue[]=[];
 for(const e of events){const f=e.fields as {[key:string]:unknown},step=text(f.step),key=`${e.node}:${e.input}:${e.run}:${step}`;
  if(e.kind==="MSG_OUTCOME"&&f.outcome==="ACCEPT"){if(step){const xs=byStep.get(key)||[];xs.push(e);byStep.set(key,xs)}last.set(`${e.node}:${e.input}:${e.run}`,e)}
  if(e.kind==="QUORUM"){
   const xs=step?byStep.get(key)||[]:[];
   // QUORUM can precede MSG_OUTCOME within its own step. Resolve below.
   out.push({quorum:e,message:xs.length===1?xs[0]!:null,confidence:step?"unknown":"inferred"});
   if(!step&&e.profile.startsWith("gstable@")&&text(f["msg.source"])&&text(f["msg.code"])) {out.at(-1)!.message=e;out.at(-1)!.confidence="inferred"}
   else if(!step){const previous=last.get(`${e.node}:${e.input}:${e.run}`);if(previous&&previous.height===e.height&&previous.round===e.round)out.at(-1)!.message=previous;else out.at(-1)!.confidence="unknown"}
  }
 }
 for(const c of out){const f=c.quorum.fields as {[key:string]:unknown},step=text(f.step);if(step){const xs=byStep.get(`${c.quorum.node}:${c.quorum.input}:${c.quorum.run}:${step}`)||[];if(xs.length===1){c.message=xs[0]!;c.confidence="step"}}}
 return out;
}
