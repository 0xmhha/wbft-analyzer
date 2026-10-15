import {describe,it,expect} from "vitest";
import {renderToStaticMarkup} from "react-dom/server";
import {timingChange,type TimingFields} from "./timing-change";
import {networkChange} from "./network-change";
import {TimingChangeEvidence} from "./views/TimingChangeEvidence";
import {SeedTimingEvidence} from "./views/SeedTimingEvidence";
import type {Schemas} from "./api/client";
const empty:TimingFields={timeout:"",period:"",cap:"",nodes:""};
describe("consensus timing changes",()=>{
 it("keeps inherited fields absent, cap removal explicit and node overrides ordered",()=>{
  const fields={timeout:"5",period:"",cap:"0",nodes:"3 - 2 -\n1 7 - -"};
  const change=timingChange(fields,4,120000000000);
  expect(change).toEqual({kind:"set_timing",from_ns:0,to_ns:120000000000,timing:{global:{request_timeout_seconds:"5",max_request_timeout_seconds:"0"},nodes:[{node:1,values:{request_timeout_seconds:"7"}},{node:3,values:{block_period_seconds:"2"}}]}});
  expect(networkChange("set_timing",0,"","0","120000000000",4,120000000000,{timing:fields})).toEqual(change);
  expect(()=>networkChange("set_timing",0,"","1","120000000000",4,120000000000,{timing:fields})).toThrow("whole registered run");
 });
 it("rejects empty, zero, unrepresentable, duplicate and unknown-node requests",()=>{
  for(const fields of [empty,{...empty,timeout:"0"},{...empty,period:"0"},{...empty,cap:"-1"},{...empty,timeout:"9223372037"},{...empty,nodes:"0 - - -"},{...empty,nodes:"0 3 - -\n0 - 2 -"},{...empty,nodes:"4 3 - -"},{...empty,nodes:"0 3 -"},{...empty,nodes:"0 3.5 - -"}])expect(()=>timingChange(fields,4,120000000000)).toThrow();
  const maximum=((9223372036854775807n-120000000000n)/1000000000n).toString();
  expect(timingChange({...empty,cap:maximum},4,120000000000).timing.global?.max_request_timeout_seconds).toBe(maximum);
  expect(()=>timingChange({...empty,cap:(BigInt(maximum)+1n).toString()},4,120000000000)).toThrow();
 });
 it("shows requested versus resolved settings and pages a 256-node model",()=>{
  const fields={...empty,nodes:Array.from({length:256},(_,i)=>`${i} 3 - 0`).join("\n")};
  const change=timingChange(fields,256,120000000000),p={request_timeout_ms:"2000",block_period_seconds:"1",max_request_timeout_seconds:"0"};
  const effect:Schemas["ScenarioTimingEffect"]={source:"resolved_simulator_configuration/1",scope:"whole_registered_run_all_incarnations",precedence:"global_then_node_explicit_fields",nodes:Array.from({length:256},(_,node)=>({node,before:p,after:{...p,request_timeout_ms:"3000"}}))};
  const html=renderToStaticMarkup(<TimingChangeEvidence change={change} effect={effect}/>);
  expect(html).toContain("Showing 1–100 of 256 requested node timing overrides");
  expect(html).toContain("Showing 1–100 of 256 resolved node timing configurations");expect(html).toContain("0 (no cap)");expect(html).toContain("2000 → 3000");expect(html).toContain("separate from the observed journals");
  expect(renderToStaticMarkup(<TimingChangeEvidence change={change}/>)).toContain("Resolved configuration evidence was not retained");
 });
 it("keeps full deadline precision and discloses bounded observed timer samples",()=>{
  const observations:Schemas["ScenarioSeedTimingObservations"]={source:"simulator_journal_segments_and_timer_events/1",timer_sampling:"first_16_and_last_16_per_node_by_time_node_run_engine_generation",journal_configurations:[{node:0,run:"run-2",engine_run:"1",journal_segments:1,chain_config_sha256:"a".repeat(64),parameters:{request_timeout_ms:"3000",block_period_seconds:"2",max_request_timeout_seconds:"0"}}],timer_coverage:[{node:0,total_round_timer_arms:"9007199254740993",retained_round_timer_arms:32}],round_timer_arms:[{node:0,run:"run-2",engine_run:"1",generation:"1",at_ns:"9007199254740993",duration_ms:"3000",deadline_ns:"9223372036854775807",height:"1",round:"0",rearmed:false},{node:0,run:"run-2",engine_run:"1",generation:"2",at_ns:"9007199254740994",duration_ms:"6000",height:"1",round:"1",rearmed:true}]};
  const html=renderToStaticMarkup(<SeedTimingEvidence observations={observations}/>);
  expect(html).toContain("9007199254740993");expect(html).toContain("9223372036854775807");expect(html).toContain("unavailable (WAL rearm)");expect(html).toContain("not a complete timer trace");expect(html).toContain("0 (no cap)");expect(html).toContain("run-2");
 });
});
