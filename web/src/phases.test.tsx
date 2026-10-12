import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import type { Schemas } from "./api/client";
import { PhaseHistogram, PhaseSeries, PhaseStats, seconds } from "./views/PhaseLatency";
it("keeps missing statistics unknown and reports counts separately", () => {
 const g: Schemas["LatencyStats"] = {node:"",profile:"",metric:"import",clock:"wall",total:3,valid:0,missing:2,negative:1,invalid_clock:0,min_seconds:null,max_seconds:null,mean_seconds:null,stddev_seconds:null,p50_seconds:null,p90_seconds:null,p95_seconds:null,p99_seconds:null,histogram:[]};
 const html=renderToStaticMarkup(<PhaseStats groups={[g]}/>);
 expect(html).toContain("Overall");expect(html).toContain("2 / 1 / 0");expect(html).toContain("unknown");expect(seconds(-.01)).toBe("-10.000 ms");
 expect(renderToStaticMarkup(<PhaseHistogram group={g}/>)).toContain("0 valid samples");
});
it("marks negative latency in the cursor-page series and omits missing measurements",()=>{
 const base: Schemas["LatencySample"]={id:"s",node:"n",profile:"gstable@abc",run:"r",height:"18446744073709551617",round:"0",metric:"preprepare",clock:"wall",status:"negative",seconds:-.01,start:null,end:null,at:"2026-10-13T00:00:00Z",duplicate_markers:0};
 const html=renderToStaticMarkup(<PhaseSeries samples={[base,{...base,id:"missing",status:"missing_end",seconds:null}]} from={base.at} to="2026-10-13T00:00:01Z"/>);
 expect(html).toContain("#b42d38");expect(html.match(/<circle/g)?.length).toBe(1);expect(html).toContain(base.height);
});
