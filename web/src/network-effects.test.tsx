import { describe,expect,it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { NetworkImpactSummary } from "./views/NetworkEffects";
import type { Schemas } from "./api/client";

describe("network influence boundary",()=>{
 it("does not call a generated model stamp a measured receive",()=>{
 const summary:Schemas["WhatifNetworkSummary"]={version:"wbft-network-effects/1",status:"unproved",scope:{status:"complete",sha256:"a".repeat(64),clock_model:"unknown",inputs:[]},bindings:1,effects:2,unchanged_under_model:0,changed_intents:2,unproved_effects:1,first_unproved_output:{execution_step:"9007199254740993",output:"2",t_mono_ns:"10"},first_observed_removed_arrival:{from_t_wall:"2026-01-01T00:00:00Z",to_t_wall:"2026-01-01T00:00:00Z",clock_model:"shared-host"}};
 const html=renderToStaticMarkup(<NetworkImpactSummary summary={summary}/>);
 expect(html).toContain("9007199254740993");expect(html).toContain("not a measured arrival");expect(html).toContain("does not establish the first network influence");expect(html).toContain("do not predict arrivals");
 });
 it("keeps historical absent evidence explicit",()=>{
 expect(renderToStaticMarkup(<NetworkImpactSummary summary={null}/>)).toContain("unavailable for this stored experiment");
 });
});
