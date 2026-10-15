import {describe,it,expect} from "vitest";
import {renderToStaticMarkup} from "react-dom/server";
import {messageChange} from "./message-change";
import type {Schemas} from "./api/client";
import {SeedMessageEvidence} from "./views/SeedMessageEvidence";
import {RecordedMessageEffect} from "./views/RecordedMessageEffect";
const row:Schemas["ScenarioRecordedMessageEvidence"]={input:"frame-a",input_sha256:"a".repeat(64),file:"frames-a.jsonl",ordinal:"9007199254740993",receiver_run:"writer",receiver:"receiver",peer:"relay",signer:"signer",height:"18446744073709551617",round:"1208925819614629174706176",phase:"PREPARE",payload_sha256:"b".repeat(64)};
describe("recorded message changes",()=>{
 it("preserves exact source ordinals and full occurrence strings",()=>{
  const change=messageChange("drop_message",[row],["18446744073709551615"],120000000000);
  expect(change.messages[0]).toEqual({input:row.input,file:row.file,ordinal:row.ordinal,model_occurrence:"18446744073709551615"});
  expect(JSON.stringify(change)).toContain('"ordinal":"9007199254740993"');
  const second={...row,ordinal:"9007199254740994",signer:"other"};
  expect(messageChange("swap_messages",[row,second],["1","2"],120000000000).messages).toHaveLength(2);
  for(const occurrence of ["0","01","-1","1.5","18446744073709551616"])expect(()=>messageChange("drop_message",[row],[occurrence],1)).toThrow();
  expect(()=>messageChange("swap_messages",[row,{...second,receiver:"other"}],["1","1"],1)).toThrow(/same recorded receiver/);
  expect(()=>messageChange("swap_messages",[row,row],["1","2"],1)).toThrow(/different original/);
 });
 it("separates a recorded request from observed delivery and actual core input",()=>{
  const change=messageChange("drop_message",[row],["1"],120000000000);
  if(change.kind!=="drop_message")throw new Error("wrong fixture kind");
  const request=renderToStaticMarkup(<RecordedMessageEffect change={change}/>);
  expect(request).toContain("9007199254740993");expect(request).toContain("Requests do not prove");expect(request).toContain("historical result");
  const observed:Schemas["ScenarioSeedMessageObservations"]={source:"simulator_transport_and_captured_message_journal/1",changes:[{kind:"drop",status:"applied",first_matches:"9007199254740993",second_matches:"0",first:{sent_ns:"1",eligible_ns:"2",peer_run:"sender-run",receiver_run:"receiver-run",simulated_payload_sha256:"c".repeat(64),arrival_order:"1",release_order:"0",capture_id:"0",offer:"",recorded_core_inputs:[]}}]};
  const html=renderToStaticMarkup(<SeedMessageEvidence observations={observed}/>);
  for(const text of ["applied","9007199254740993","not delivered","no capture","no receiver invocation","No recorded core input","No second selection requested"])expect(html).toContain(text);
  expect(html).not.toContain("deduplicated");
  observed.changes[0]!.first=undefined;observed.changes[0]!.status="unmatched";
  expect(renderToStaticMarkup(<SeedMessageEvidence observations={observed}/>)).toContain("No eligible packet matched");
 });
});
