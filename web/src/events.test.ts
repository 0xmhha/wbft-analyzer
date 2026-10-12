import { describe, expect, it } from "vitest";
import { eventKey, eventLayout, field, timeWindow } from "./events";
import type { LogEvent } from "./events";
const e:LogEvent={input:"log-1",line:900719,node:"node1",run:"log-1:3",t_wall:"2026-10-13T00:00:01Z",kind:"ROUND_ENTER",height:"18446744073709551617",round:"340282366920938463463374607431768211456",level:"info",profile:"gstable@740526d03",view_inferred:false,fields:{phase:"COMMIT",nested:{payload:"secret"}}};
describe("log metadata layout",()=>{
 it("keeps source pointers and full consensus values intact",()=>{
  const rows=eventLayout([e],["node1","node2"],"2026-10-13T00:00:00Z","2026-10-13T00:00:02Z");
  expect(rows[0]?.x).toBe(550);expect(rows[0]?.y).toBe(52);
  expect(rows[0]?.event.height).toBe("18446744073709551617");expect(rows[0]?.event.round).toBe("340282366920938463463374607431768211456");expect(eventKey(e)).toBe("log-1:900719");
 });
 it("does not render nested metadata or nodes outside the filter",()=>{
  expect(field(e,"phase")).toBe("COMMIT");expect(field(e,"nested")).toBe("");expect(eventLayout([e],["node2"],e.t_wall,e.t_wall)).toEqual([]);
 });
 it("clamps zoom and pan to stored run bounds",()=>{
  const bounds={from_t:"2026-10-13T00:00:00Z",to_t:"2026-10-13T00:01:00Z"};
  expect(timeWindow(Date.parse("2026-10-13T00:10:00Z"),30000,bounds)).toEqual({from_t:"2026-10-13T00:00:30.000Z",to_t:"2026-10-13T00:01:00.000Z"});
  expect(timeWindow(0,120000,bounds)).toEqual({from_t:"2026-10-13T00:00:00.000Z",to_t:"2026-10-13T00:01:00.000Z"});
 });
});

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { Swimlanes } from "./views/Events";
it("adds the source event lane when a direct source jump lies outside the page filter",()=>{
 const selected={...e,node:"node2"};
 const html=renderToStaticMarkup(createElement(Swimlanes,{events:[],nodes:["node1"],from:"2026-10-13T00:00:00Z",to:"2026-10-13T00:00:02Z",selected,onSelect:()=>{}}));
 expect(html).toContain("node2");expect(html).toContain("event-selected");expect(html).toContain('cy="110"');
});
