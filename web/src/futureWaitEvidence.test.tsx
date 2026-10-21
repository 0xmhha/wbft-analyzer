import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { LogEvent } from "./events";
import { FutureWaitEvidence } from "./views/FutureWaitEvidence";

const source:LogEvent={height:"18446744073709551616",input:"wait-events",level:"event",line:2,node:"node-1",profile:"wbft-events",round:"1",run:"normal-wait-1",t_wall:"2026-01-01T00:00:00Z",view_inferred:false,kind:"HEALTH",fields:{what:"future_proposal_wait_exceeded",proposal_origin:"preprepare",wait_ns:"9007199254740993",limit_ns:"9007199254740992"}};
describe("recorded proposal wait rejection",()=>{
 it("retains exact requested wait and limit without a JavaScript number conversion",()=>{
  const html=renderToStaticMarkup(<FutureWaitEvidence event={source}/>);
  expect(html).toContain("Received proposal");expect(html).toContain("9007199254740993");expect(html).toContain("9007199254740992");expect(html).toContain("do not measure elapsed or remaining time");expect(html).toContain("future-wait-evidence");
 });
 it("distinguishes the local prepared candidate",()=>{
  const event={...source,fields:{...(source.fields as Record<string,unknown>),proposal_origin:"local_reproposal"}};
  const html=renderToStaticMarkup(<FutureWaitEvidence event={event}/>);
  expect(html).toContain("Local prepared candidate");expect(html).not.toContain("Received proposal");
 });
 it("keeps incomplete retained metadata visibly unknown",()=>{
  const event={...source,fields:{what:"future_proposal_wait_exceeded"}};
  const html=renderToStaticMarkup(<FutureWaitEvidence event={event}/>);
  expect(html).toContain("Proposal origin unavailable");expect(html.match(/<code>unknown<\/code>/g)).toHaveLength(2);
 });
 it("does not label an ordinary different event as a wait rejection",()=>{
  expect(renderToStaticMarkup(<FutureWaitEvidence event={{...source,kind:"NEW_HEAD",fields:{number:"1"}}}/>)).toBe("");
 });
});
