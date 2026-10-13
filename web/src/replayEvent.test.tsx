import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { ReplayEventList } from "./views/ReplayEventEvidence";

describe("recorded replay event evidence",()=>{
 it("opens the exact original dataset/input/line without numeric truncation",()=>{
 const html=renderToStaticMarkup(<ReplayEventList net={7} evidence={{status:"matched",event_dataset_id:9,source_ordinal:11,events:[{input:"node-events",line:42,node:"node",run:"writer",t_wall:"2020-01-01T00:00:00Z",kind:"STATE",height:"18446744073709551615",round:"0",level:"",profile:"wbft@events-v1",view_inferred:false,fields:{}}]}}/>);
 expect(html).toContain("dataset=9&amp;input=node-events&amp;line=42&amp;replay=1");expect(html).toContain("18446744073709551615");expect(html).toContain("does not establish core reproduction");
 });
 it("keeps unavailable identity visible and offers no inferred source link",()=>{
 const html=renderToStaticMarkup(<ReplayEventList net={7} evidence={{status:"unavailable",reason:"no_explicit_step_events",event_dataset_id:9,source_ordinal:11,events:[]}}/>);
 expect(html).toContain("no_explicit_step_events");expect(html).toContain("classifications are unchanged");expect(html).not.toContain("href=");
 });
});
