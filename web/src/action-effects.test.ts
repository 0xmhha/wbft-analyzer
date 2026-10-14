import { describe,expect,it } from "vitest";
import { networkComparison } from "./action-effects";
import type { Schemas } from "./api/client";
type Action=Schemas["WhatifAction"];
const timer:Action={output:"1",kind:"arm_timer",output_sha256:"a".repeat(64),height:"9007199254740993",round:"0",timer:"1",duration_ns:"1000000000",eligible_recipients:[],recipient_evidence:"not_network",payload_evidence:"not_network"};
const message:Action={output:"2",kind:"broadcast",output_sha256:"b".repeat(64),code:"2",eligible_recipients:["0x"+"c".repeat(40)],recipient_evidence:"validator_set",payload_evidence:"recorded_signing_result",payload_sha256:"d".repeat(64)};
describe("network intent evidence",()=>{
 it("does not turn a changed timer fingerprint into changed network bytes",()=>{
  const changed={...timer,output_sha256:"e".repeat(64),duration_ns:"2000000000"};
  expect(networkComparison({output_actions:[changed,message],recorded_output_actions:[timer,message]})).toBe("same");
  expect(networkComparison({output_actions:[changed],recorded_output_actions:[timer]})).toBe("none");
 });
 it("shows removed original or added generated intents without guessing delivery",()=>{
  expect(networkComparison({output_actions:[],recorded_output_actions:[message]})).toBe("changed");
  expect(networkComparison({output_actions:[message],recorded_output_actions:[]})).toBe("changed");
 expect(networkComparison({output_actions:[message],recorded_output_actions:[],generated:true})).toBe("generated");
  expect(networkComparison({output_actions:[{...message,eligible_recipients:[]}],recorded_output_actions:[message]})).toBe("changed");
 });
 it("keeps unavailable bytes and historical missing evidence explicit",()=>{
  const unsigned={...message,payload_evidence:"unsigned_request",payload_sha256:undefined};
  expect(networkComparison({output_actions:[unsigned],recorded_output_actions:[unsigned]})).toBe("unknown");
  expect(networkComparison({output_actions:null,recorded_output_actions:null})).toBe("unavailable");
 });
});
