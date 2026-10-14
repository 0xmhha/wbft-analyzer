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
});
