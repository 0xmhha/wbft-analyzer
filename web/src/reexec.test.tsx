import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { Schemas } from "./api/client";
import { parseRoute } from "./App";
import { ReexecSummary } from "./views/Reexec";

describe("closed replay evidence",()=>{
 it("keeps partial inputs and unknown versions visible without numeric truncation",()=>{
 const run:Schemas["StoreReexecRun"]={id:1,dataset_id:2,input_id:"journal",from_height:"1",to_height:"2",created_at:"2026-01-01T00:00:00Z",finished_at:null,status:"partial",summary:{version:"wbft-closed-reexec/1",status:"partial",helper_version:"unknown",binary_version:"unknown",helper_sha256:"a".repeat(64),version_status:"unknown",source_sha256:"b".repeat(64),chain_sha256:"c".repeat(64),source_versions:["unknown"],heights:[{height:"18446744073709551616",status:"partial",issues:["wire_association"],steps:1}],steps:1,matches:0,mismatches:0,not_comparable:1}};
 const html=renderToStaticMarkup(<ReexecSummary run={run}/>);
 expect(html).toContain("Regression comparison");expect(html).toContain("18446744073709551616");expect(html).toContain("wire_association");expect(html).toContain("not comparable");expect(html).not.toContain("reproduced");
 });
 it("routes core replay separately from recorded event playback",()=>{expect(parseRoute("#/networks/7/reexec")).toEqual({view:"reexec",net:7});expect(parseRoute("#/networks/7/events").view).toBe("events")});
});
