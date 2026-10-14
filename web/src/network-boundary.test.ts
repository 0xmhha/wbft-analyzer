import { describe,expect,it } from "vitest";
import { impactRegion,wallNanoseconds } from "./network-boundary";
import type { Schemas } from "./api/client";

describe("exact influence regions",()=>{
 it("keeps a one-nanosecond boundary and refuses invalid calendars",()=>{
 const a=wallNanoseconds("2026-01-01T00:00:00.000000001Z"),b=wallNanoseconds("2026-01-01T00:00:00.000000002Z");
 expect(a).not.toBeNull();expect(b!-a!).toBe(1n);expect(wallNanoseconds("2026-02-30T00:00:00Z")).toBeNull();
 });
 it("does not manufacture wall stamps for generated input or call uncertain rows valid",()=>{
 const summary:Schemas["WhatifNetworkSummary"]={version:"wbft-network-effects/1",status:"bounded_original_delivery",scope:{status:"complete",clock_model:"shared-host",sha256:"a".repeat(64),inputs:[]},bindings:1,effects:1,unchanged_under_model:0,changed_intents:1,unproved_effects:0,first_unproved_output:null,first_observed_removed_arrival:{from_t_wall:"2026-01-01T00:00:00.000000002Z",to_t_wall:"2026-01-01T00:00:00.000000002Z",clock_model:"shared-host"}};
 const step={execution_step:"3",source_entry_t_wall:"2026-01-01T00:00:00.000000001Z"} as Schemas["WhatifStep"];
 expect(impactRegion(step,summary)).toBe("before");step.source_entry_t_wall="2026-01-01T00:00:00.000000002Z";expect(impactRegion(step,summary)).toBe("potential_original_influence");
 step.source_entry_t_wall=null;expect(impactRegion(step,summary)).toBe("unaligned");
 summary.status="unproved";summary.first_unproved_output={execution_step:"9007199254740993",output:"1",t_mono_ns:"3"};step.execution_step="9007199254740994";expect(impactRegion(step,summary)).toBe("unproved");
 });
});
