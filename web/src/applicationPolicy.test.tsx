import { describe,expect,it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { Schemas } from "./api/client";
import { ApplicationPolicies } from "./views/Scenarios";

describe("application startup evidence",()=>{
 it("preserves every startup and distinguishes declarations from physical proof",()=>{
  const first:Schemas["ScenarioApplicationPolicy"]={node:"node-a",input:"events-a",run:"writer-one",line:17,status:"declared_simulator",build_queue:"serial-latest",done_result:"failed",assembly_return:"sampled",selection:"callbacks_then_done_then_pending"};
  const missing:Schemas["ScenarioApplicationPolicy"]={...first,run:"writer-two",line:91,status:"unavailable",build_queue:"",done_result:"",assembly_return:"",selection:""};
  const html=renderToStaticMarkup(<ApplicationPolicies policies={[first,missing]}/>);
  expect(html).toContain("Application startup declarations (2)");
  expect(html).toContain("writer writer-one · line 17 · declared_simulator");
  expect(html).toContain("writer writer-two · line 91 · unavailable");
  expect(html).toContain("Build queue: unavailable");
  expect(html).toContain("successful timings do not prove a physical executor model");
 });
 it("shows sealing inputs without losing large ns strings or sample multiplicity",()=>{
  const policy:Schemas["ScenarioApplicationPolicy"]={node:"node-a",input:"events-a",run:"writer-one",line:19,status:"declared_simulator",build_queue:"unbuffered-seal",done_result:"",assembly_return:"sampled_empty_body",selection:"actors_to_idle_then_deadline_callbacks_seeded",sealing:{running_gate:"at_selection",commit_capacity:1,result_capacity:10,head_capacity:10,pending_age:7,call_return_delay_ns:["0","9007199254740993","0"],post_delay_ns:["2"],assembly_delay_ns:["7","2","7"],import_delay_ns:["3"]}};
  const html=renderToStaticMarkup(<ApplicationPolicies policies={[policy]}/>);
  expect(html).toContain("writer writer-one · line 19 · declared_simulator");
  expect(html).toContain("request Done ignored");
  expect(html).toContain("commit 1 · result 10 · head 10");
  expect(html).toContain("0, 9007199254740993, 0");
  expect(html).toContain("7, 2, 7");
 });

});
