import {expect,it} from "vitest";
import {selectFlowMetric,flowMarks,flowFraction} from "./messageFlow";
import type {Pair} from "./messageFlow";
import {stampNs} from "./replay";
const base:Pair={id:"p",at:"2020-01-01T00:00:00Z",sender:"a",receiver:"b",phase:"PREPARE",height:"18446744073709551617",round:"0",metric:"link",strength:"link",path:"direct",status:"valid",clock:"shared-host",send:{kind:"message",input:"j1",ordinal:1,node:"a",run:"r",t_wall:"2020-01-01T00:00:00Z"},receive:{kind:"message",input:"j2",ordinal:1,node:"b",run:"r",t_wall:"2020-01-01T00:00:01Z"},send_candidates:1,receive_candidates:1,candidates:[],views:[],seconds:1,raw_seconds:1,lower_seconds:1,upper_seconds:1,observed_from:"2020-01-01T00:00:00Z",observed_to:"2020-01-01T00:00:01Z"};
it("animates only the interval between unique valid link endpoints",()=>{const m=flowMarks([base])[0]!;expect(flowFraction(m,stampNs("2020-01-01T00:00:00.5Z"))).toBe(.5);expect(flowFraction(m,stampNs("2019-12-31T23:59:59Z"))).toBeNull();for(const p of [{...base,status:"ambiguous"},{...base,status:"unknown_clock",clock:"unknown"},{...base,strength:"node",metric:"propagation_processing"},{...base,status:"negative"}])expect(flowFraction(flowMarks([p])[0]!,stampNs("2020-01-01T00:00:00.5Z"))).toBeNull()});
it("retains elapsed clock bands without converting unknown clocks to zero",()=>{const m=flowMarks([{...base,clock:"ntp",lower_seconds:.8,upper_seconds:1.2}])[0]!;expect(m.band).toEqual([stampNs("2020-01-01T00:00:00.8Z"),stampNs("2020-01-01T00:00:01.2Z")]);expect(flowMarks([{...base,clock:"unknown",lower_seconds:null,upper_seconds:null}])[0]!.band).toBeNull();expect(flowMarks([{...base,receive_candidates:2}])[0]!.connected).toBe(false)});

it("excludes later event endpoints at an exact source cut without changing original evidence",()=>{const pair={...base,send:{...base.send!,kind:"event",input:"e",ordinal:1},receive:{...base.receive!,kind:"event",input:"e",ordinal:3,t_wall:base.send!.t_wall}};const m=flowMarks([pair],{dataset:1,input:"e",line:1,at:stampNs(base.send!.t_wall)})[0]!;expect(m.send).not.toBeNull();expect(m.receive).toBeNull();expect(m.connected).toBe(false);expect(m.pair.receive_candidates).toBe(1)});

it("keeps measured I/O animation separate from callback motion and requires exact boundaries",()=>{
 const io:Pair={...base,id:"io",metric:"write_start_to_read_complete",send:{...base.send!,moment:"write_start",callback_t_wall:"2020-01-01T00:00:02Z"},receive:{...base.receive!,moment:"read_complete",callback_t_wall:"2020-01-01T00:00:01.1Z"}};
 expect(selectFlowMetric([base,io],"recorded")).toEqual([base]);expect(selectFlowMetric([base,io],"write_start_to_read_complete")).toEqual([io]);
 expect(flowFraction(flowMarks([io])[0]!,stampNs("2020-01-01T00:00:00.5Z"))).toBe(.5);
 expect(flowMarks([{...io,send:{...io.send!,moment:undefined}}])[0]!.animate).toBe(false);
});
