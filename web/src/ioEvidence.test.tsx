import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { IOEvidence } from "./views/IOEvidence";

describe("transport I/O evidence",()=>{
 it("preserves zero and large nanoseconds beside regressing wall timestamps",()=>{
  const html=renderToStaticMarkup(<IOEvidence interval={{start_mono_ns:"0",end_mono_ns:"9007199254740993",start_wall:"2020-01-01T00:00:00.0000001Z",end_wall:"2020-01-01T00:00:00.00000009Z"}}/>);
  expect(html).toContain("9007199254740993");expect(html).toContain("2020-01-01T00:00:00.0000001Z");expect(html).toContain("2020-01-01T00:00:00.00000009Z");expect(html).toContain("callback time remains separate");expect(html).toContain("do not establish corrected latency");
 });
 it("keeps unmeasured intervals unavailable",()=>{
  const html=renderToStaticMarkup(<IOEvidence/>);expect(html).toContain("I/O interval unavailable");expect(html).toContain("does not supply missing endpoints");expect(html).not.toContain("Start monotonic ns");
 });
});
