import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { Schemas } from "./api/client";
import { get } from "./api/client";
import { SyncControlEvidence, getSyncSource, matchesSyncSource } from "./views/SyncControlEvidence";
vi.mock("./api/client",()=>({get:vi.fn()}));
type Record = Schemas["MessagesRecord"];
const point={input:"sync",file:"frames-sync.jsonl",ordinal:3,seq:"3"};
const requested={stage:"requested",request:"1",operation:"0",syncing:true,success:false,first_before:false,first_after:false,running_before:false,running_after:false,action:"",failed:false,events_available:false,event_before:"0",event_after:"0",sequence_exhausted:false};
const parent:Record={input:"sync",file:point.file,ordinal:2,seq:"2",node:"self",run:"writer",type:"sync_control",clock_source:"recorded",t_mono_ns:"4",sync_control:{...requested,stage:"processed",operation:"1",running_before:true,action:"stop",events_available:true,event_before:"9007199254740993",event_after:"9007199254740995",request_source:{source_available:true,source_seq:"3",source_segment:"0",source_offset:"42"}},sync_evidence:{declaration:{...point,ordinal:1,seq:"1"},request:point,complete:true}};
const original:Record={...parent,...point,journal_position:{segment:"0",offset:"42"},sync_control:requested,sync_evidence:{declaration:parent.sync_evidence!.declaration,complete:true}};
const render=(record:Record)=>renderToStaticMarkup(<SyncControlEvidence net={7} dataset={11} record={record} onAuth={()=>{}}/>);
describe("recorded sync source",()=>{
 it("opens the original ordinal independently of event cursor values",async()=>{vi.mocked(get).mockResolvedValue({} as never);await getSyncSource(7,11,point);expect(get).toHaveBeenCalledWith("/v1/networks/{net}/datasets/{dataset}/messages/source",{path:{net:7,dataset:11},query:{input:"sync",file:point.file,ordinal:"3"}})});
 it("validates identity, exact journal position and submitted state",()=>{
  expect(matchesSyncSource(parent,original,"request")).toBe(true);
  for(const change of [{node:"other"},{run:"other"},{seq:"4"},{ordinal:4},{file:"other.jsonl"},{journal_position:{segment:"1",offset:"42"}},{journal_position:{segment:"0",offset:"43"}},{sync_control:{...requested,request:"2"}},{sync_control:{...requested,success:true}},{sync_control:{...requested,syncing:null}}])expect(matchesSyncSource(parent,{...original,...change},"request")).toBe(false);
 });
 it("shows full cursor strings and separates coverage from a verdict",()=>{
  const html=render(parent);
  for(const label of ["Recorded sync controls","9007199254740993","9007199254740995","separate from journal seq","Source coverage does not decide consensus conformance","independently verify the downloader","Open original sync request","First successful sync seen","Complete recorded context"])expect(html).toContain(label);
  expect(html).not.toContain("PASS");
 });
 it("keeps incomplete requests unavailable and shows no artificial source button",()=>{
  const html=render({...parent,sync_control:{...parent.sync_control!,request_source:{source_available:false}},sync_evidence:{declaration:parent.sync_evidence!.declaration,complete:false}});
  expect(html).toContain("Incomplete recorded context");expect(html).toContain("no coordinates were inferred");expect(html).not.toContain("Open original sync request");
 });
 it("does not display request padding as a measured engine/guard state",()=>{
  const html=render(original);
  expect(html).toContain("Submitted notification");expect(html).toContain("Engine and guard state are not measured");expect(html).not.toContain("Engine running (recorded)");expect(html).not.toContain("First successful sync seen");expect(html).not.toContain("Recorded event cursor range");
 });
 it("retains failed calls, empty ranges and explicit sequence exhaustion",()=>{
  const html=render({...parent,sync_control:{...parent.sync_control!,request:"0",operation:"0",failed:true,event_after:parent.sync_control!.event_before,sequence_exhausted:true,request_source:{source_available:false}},sync_evidence:{declaration:parent.sync_evidence!.declaration,complete:false}});
  expect(html).toContain("call error recorded: yes");expect(html).toContain("unavailable (recorded 0)");expect(html).toContain("Control identity sequence exhausted");expect(html).toContain("Recorded event cursor range");expect(html).not.toContain("Open original sync request");
 });
 it("leaves legacy records unchanged",()=>{expect(render({input:"old",file:"frames.jsonl",ordinal:1,seq:"1",node:"self",run:"old",type:"frame"})).toBe("")});
});
