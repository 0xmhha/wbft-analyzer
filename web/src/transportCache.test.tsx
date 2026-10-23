import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { LogEvent } from "./events";
import { transportCacheDeclaration } from "./transportCache";
import { TransportCachePolicy } from "./views/TransportCachePolicy";

const fields = {
  transport_cache_profile: "accepted_completed_v1", transport_cache_active: true,
  transport_cache_receive_pending: "9007199254740993", transport_cache_receive_per_peer: "8",
  transport_cache_write_pending: "18446744073709551615", transport_cache_write_per_peer: "16",
};
const source = { kind: "NODE_START", fields } as LogEvent;

describe("recorded transport cache declaration", () => {
  it("preserves exact counts and distinguishes configured gates from measured operations", () => {
    const html = renderToStaticMarkup(<TransportCachePolicy event={source}/>);
    for (const text of ["Active at startup", "9007199254740993", "18446744073709551615", "Direct core ACCEPT", "Successful local write", "no measured cache transitions", "Queue admission does not establish a successful write"]) expect(html).toContain(text);
  });
  it("retains an explicitly inactive declaration", () => {
    const html = renderToStaticMarkup(<TransportCachePolicy event={{ ...source, fields: { ...fields, transport_cache_active: false } }}/>);
    expect(html).toContain("Inactive at startup");
    expect(html).not.toContain("<strong>Active at startup");
  });
  it("refuses missing, noncanonical and out-of-range counts and inconsistent limits", () => {
    for (const value of [undefined, 16, "0", "01", "18446744073709551616", "1e3"]) expect(transportCacheDeclaration({ ...fields, transport_cache_write_pending: value })).toBeNull();
    expect(transportCacheDeclaration({ ...fields, transport_cache_receive_pending: "4" })).toBeNull();
    expect(transportCacheDeclaration({ ...fields, transport_cache_active: "true" })).toBeNull();
    const html = renderToStaticMarkup(<TransportCachePolicy event={{ ...source, fields: { ...fields, transport_cache_profile: "future" } }}/>);
    expect(html).toContain("Cache policy declaration unavailable");
    expect(html).not.toContain("Known entry");
    expect(renderToStaticMarkup(<TransportCachePolicy event={{ ...source, fields: { transport_cache_profile: "unavailable" } }}/>)).toContain("Cache policy declaration unavailable");
  });
  it("does not infer a policy from old startup records or other event kinds", () => {
    expect(renderToStaticMarkup(<TransportCachePolicy event={{ ...source, fields: {} }}/>)).toBe("");
    expect(renderToStaticMarkup(<TransportCachePolicy event={{ ...source, kind: "NEW_HEAD" }}/>)).toBe("");
  });
});
