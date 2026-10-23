import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { DeferredEvidence } from "./views/DeferredEvidence";

describe("deferred message source", () => {
 it("keeps the original capture and refuses a cross-writer duration", () => {
  const html = renderToStaticMarkup(<DeferredEvidence writer="second-writer" evidence={{
   origin: {writer_run: "first-writer", capture_id: "9007199254740993"},
   status: "verified", receipt_mono_ns: "9"
  }}/>);
  expect(html).toContain("first-writer");
  expect(html).toContain("9007199254740993");
  expect(html).toContain("another writer clock; elapsed time is unavailable");
 });

 it("keeps missing physical evidence separate from functional replay", () => {
  const html = renderToStaticMarkup(<DeferredEvidence writer="second-writer" evidence={{
   origin: {writer_run: "first-writer", capture_id: "17"},
   status: "unavailable", reason: "missing_capture"
  }}/>);
  expect(html).toContain("missing_capture");
  expect(html).toContain("functional replay remains independent of capture retention");
  expect(html).not.toContain("Original receipt");
 });
});
