import {describe,expect,it} from "vitest";
import {renderToStaticMarkup} from "react-dom/server";
import {RoundChangeClaims} from "./views/Nodes";

describe("round-change RPC claims",()=>{
 it("keeps uncaptured and unsupported claims distinct from an observed zero",()=>{
  let html=renderToStaticMarkup(<RoundChangeClaims comparison={undefined}/>);
  expect(html).toContain("not captured");expect(html).toContain("does not establish zero changes");expect(html).not.toContain("<td>0</td>");
  html=renderToStaticMarkup(<RoundChangeClaims comparison={{status:"unavailable",computed_count:0,different_fields:[]}}/>);
  expect(html).toContain("<td>0</td><td>unavailable</td><td>unavailable</td>");expect(html).toContain("original request availability");
 });
 it("shows matching recorded counts without claiming complete round-change history",()=>{
  const html=renderToStaticMarkup(<RoundChangeClaims comparison={{status:"match",computed_count:1,reported_count:1,different_rows:0,different_fields:[]}}/>);
  expect(html).toContain("comparison: match");expect(html).toContain("<td>1</td><td>1</td><td>0</td>");expect(html).toContain("Gaps and header-only rows cannot establish complete local round-change history");
 });
 it("preserves disagreement and source availability",()=>{
  const html=renderToStaticMarkup(<RoundChangeClaims comparison={{status:"different",computed_count:1,reported_count:1,different_rows:1,different_fields:["cause"]}}/>);
  expect(html).toContain("comparison: different");expect(html).toContain("Different round-change fields: cause");expect(html).toContain("Both original requests remain available");
 });
});
