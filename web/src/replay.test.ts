import { expect,it } from "vitest";
import { apply,empty,Projection,quorumCues,stampNs,nsStamp,sourcePosition } from "./replay";
import type { Record,Window } from "./replay";
const base:Record={input:"e",line:1,node:"n",run:"r",profile:"wbft@events-v1",source:"event",level:"event",t_wall:"2026-10-13T00:00:00.123456789Z",t_mono_ns:"0",kind:"ROUND_ENTER",height:"18446744073709551617",round:"340282366920938463463374607431768211456",view_inferred:false,fields:{cause:"timeout"}};
it("preserves the precise axis and full view without treating message view as node view",()=>{
 expect(nsStamp(stampNs(base.t_wall))).toBe(base.t_wall);expect(stampNs(base.t_wall)-stampNs("2026-10-13T00:00:00.123456788Z")).toBe(1n);
 const s=empty("n");apply(s,base);apply(s,{...base,kind:"MSG_OUTCOME",height:"7",round:"0",fields:{outcome:"ACCEPT"}});expect(s.view?.seq).toBe(base.height);expect(s.state).toBe("");
 apply(s,{...base,kind:"TIMER_ARM",fields:{timer:"round",gen:"4",engine_run:"1",deadline_mono_ns:"100"}});
 apply(s,{...base,kind:"TIMER_CANCEL",fields:{timer:"round",gen:"3",engine_run:"1"}});expect(s.timers.round?.status).toBe("armed");expect(s.unmatched_timer_events).toBe(1);
 apply(s,{...base,kind:"TIMER_FIRE",fields:{timer:"round",gen:"4",engine_run:"1",stale:true}});expect(s.timers.round?.status).toBe("armed");
 apply(s,{...base,kind:"TIMER_CANCEL",fields:{timer:"round",gen:"4",engine_run:"1"}});expect(s.timers.round?.status).toBe("cancelled");expect(s.timers.round?.closed?.line).toBe(1);
});
it("local keyframes match full prefixes at arbitrary source positions",()=>{
 const events:Record[]=[base];for(let i=2;i<=6000;i++)events.push({...base,line:i,kind:"BACKLOG",fields:{op:"push"},t_wall:nsStamp(stampNs(base.t_wall)+BigInt(i))});
 const data:Window={version:"test",events,nodes:[{node:"n",initial:{state:empty("n"),keyframe:null,tail_records:0,version:"test"},levels:["events"],sequence_gaps:0,monotonic_regressions:0,wall_regressions:0}]};const model=new Projection(data);
 for(let j=0;j<100;j++){const n=(j*127)%6001,s=empty("n");for(const e of events.slice(0,n))apply(s,e);expect(model.seek(n).n).toEqual(s)}
 expect(model.indexAt(stampNs(base.t_wall))).toBe(1);
});
it("uses the one accepted message of a quorum step even when outcome is emitted later",()=>{
 const q={...base,kind:"QUORUM",fields:{what:"PREPARE",step:"9"}},m={...base,line:2,kind:"MSG_OUTCOME",fields:{step:"9",outcome:"ACCEPT"}};
 const c=quorumCues([q,m])[0];expect(c?.confidence).toBe("step");expect(c?.message?.line).toBe(2);
 expect(quorumCues([q,m,{...m,line:3}])[0]?.confidence).toBe("unknown");
 const legacy={...q,profile:"gstable@740526d03",fields:{what:"PREPARE","msg.source":"0x"+"1".repeat(40),"msg.code":"19"}};expect(quorumCues([legacy])[0]?.confidence).toBe("inferred");
});

it("selects an exact source within equal timestamps and never invents a filtered point",()=>{
 const events:Record[]=[base,{...base,line:2},{...base,line:3}];
 const data:Window={version:"test",events,nodes:[{node:"n",initial:{state:empty("n"),keyframe:null,tail_records:0,version:"test"},levels:["events"],sequence_gaps:0,monotonic_regressions:0,wall_regressions:0}]};
 const at=sourcePosition(new Projection(data),events[1]);expect(at.index).toBe(2);expect(at.selected?.line).toBe(2);expect(at.at).toBe(base.t_wall);
 const hidden=sourcePosition(new Projection(data),{...base,input:"other",node:"other"});expect(hidden.index).toBe(3);expect(hidden.selected).toBeNull();
});
