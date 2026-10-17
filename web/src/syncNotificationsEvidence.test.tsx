import {describe,expect,it,vi} from "vitest";
import {renderToStaticMarkup} from "react-dom/server";
import type {Schemas} from "./api/client";
import {get} from "./api/client";
import {SyncNotificationEvidence,getTypedSyncSource,matchesTypedSyncSource} from "./views/SyncNotificationEvidence";
vi.mock("./api/client",()=>({get:vi.fn()}));
type Record=Schemas["MessagesRecord"];
const headerPoint={input:"typed",file:"notifications.jsonl",ordinal:1,seq:""};
const footerPoint={...headerPoint,ordinal:8};
const proof={header:headerPoint,footer:footerPoint,retained_complete:true};
const base={input:"typed",file:"notifications.jsonl",node:"0xaa00000000000000000000000000000000000000",run:"source-run",sync_notification_evidence:proof};
const parent:Record={...base,ordinal:5,seq:"4",type:"sync_notification",clock_source:"downloader_posted",t_wall:"2026-01-01T00:00:00Z",sync_notification:{type:"notification",sequence:"4",kind:"done",posted_at_available:true,posted_at:"2026-01-01T00:00:00Z",number:"9007199254740993",hash:"0xbb00000000000000000000000000000000000000000000000000000000000000"}};
const header:Record={...base,ordinal:1,seq:"",type:"sync_notification_source",sync_notification_source:{format:"wbft-sync-notifications/1",stage:"header",header:{format:"wbft-sync-notifications/1",type:"header",node:base.node,run:base.run,validator:true,core_start_seq:"0"}}};
const footer:Record={...base,ordinal:8,seq:"",type:"sync_notification_source",sync_notification_source:{format:"wbft-sync-notifications/1",stage:"footer",footer:{type:"footer",observed:"6",written:"6",dropped:"0",invalid:"0",sequence_exhausted:false,core_complete:true,core_stop_seq:"9007199254740995",closed_normally:true,complete:true}}};
const render=(r:Record)=>renderToStaticMarkup(<SyncNotificationEvidence net={7} dataset={11} record={r} onAuth={()=>{}}/>);

describe("typed downloader notification sources",()=>{
 it("opens exact original file rows without manufacturing sequences",async()=>{vi.mocked(get).mockResolvedValue({} as never);await getTypedSyncSource(7,11,footerPoint);expect(get).toHaveBeenCalledWith("/v1/networks/{net}/datasets/{dataset}/messages/source",{path:{net:7,dataset:11},query:{input:"typed",file:"notifications.jsonl",ordinal:"8"}})});
 it("matches header/footer identity and their absent source sequences",()=>{
  expect(matchesTypedSyncSource(parent,header,"header")).toBe(true);expect(matchesTypedSyncSource(parent,footer,"footer")).toBe(true);
  for(const change of [{node:"other"},{run:"other"},{input:"other"},{file:"other.jsonl"},{ordinal:2},{seq:"0"},{type:"frame"}])expect(matchesTypedSyncSource(parent,{...header,...change},"header")).toBe(false);
  expect(matchesTypedSyncSource(parent,{...header,sync_notification_source:{...header.sync_notification_source!,header:{...header.sync_notification_source!.header!,node:"other"}}},"header")).toBe(false);
  expect(matchesTypedSyncSource(parent,{...footer,sync_notification_evidence:{...proof,retained_complete:false}},"footer")).toBe(false);
 });
 it("keeps producer completeness separate from incomplete retained bytes",()=>{
  const incomplete={...proof,retained_complete:false};expect(matchesTypedSyncSource({...parent,sync_notification_evidence:incomplete},{...footer,sync_notification_evidence:incomplete},"footer")).toBe(true);
  const html=render({...footer,sync_notification_evidence:incomplete});expect(html).toContain("Incomplete retained file");expect(html).toContain("Producer reports complete: yes");expect(html).toContain("9007199254740995");expect(html).not.toContain("PASS");
 });
 it("shows exact downloaded headers and independent posting clocks",()=>{
  const html=render(parent);for(const text of ["Typed downloader notifications","9007199254740993","Posting clock:","separate from journal positions and consensus event sequences","does not prove consensus correctness","Open original notification header","Open original notification footer"])expect(html).toContain(text);expect(html).not.toContain("PASS");expect(html).not.toContain("Engine running");
 });
 it("shows an unavailable clock and omits a nonexistent footer action",()=>{
  const html=render({...parent,t_wall:undefined,sync_notification:{type:"notification",sequence:"2",kind:"failed",posted_at_available:false},sync_notification_evidence:{header:headerPoint,retained_complete:false}});expect(html).toContain("Posting clock: unavailable");expect(html).toContain("Original footer unavailable");expect(html).not.toContain("Open original notification footer");
 });
 it("preserves absent original sequences on source headers and footers",()=>{
  expect(render(header)).toContain("This header has no original notification sequence");expect(render(footer)).toContain("This footer has no original notification sequence");expect(render(footer)).toContain("observed 6");expect(render(footer)).toContain("sequence exhausted: no");
 });
 it("leaves unrelated historical records unchanged",()=>{expect(render({input:"old",file:"frames.jsonl",ordinal:1,seq:"1",node:"self",run:"old",type:"frame"})).toBe("")});
});
