import type { Schemas } from "./api/client";

export type EventFocus = { dataset: number; input: string; line: number; replay: boolean };
const identifier = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
function positive(value: string | null): number | null {
 if (!value || !/^[1-9]\d*$/.test(value)) return null;
 const n = Number(value);
 return Number.isSafeInteger(n) ? n : null;
}

/** URL source pointers never choose a file or fetch outside the network API. */
export function eventFocus(query: string): { focus?: EventFocus; sourceError?: string } {
 const q = new URLSearchParams(query);
 if (!q.size) return {};
 const allowed = ["dataset", "input", "line", "replay"];
 const dataset = positive(q.get("dataset")), line = positive(q.get("line")), input = q.get("input") || "";
 if ([...q.keys()].some(k => !allowed.includes(k) || q.getAll(k).length !== 1) || !dataset || !line || !identifier.test(input) || q.has("replay") && q.get("replay") !== "1") return { sourceError: "Invalid event source link; no source was selected." };
 return { focus: { dataset, input, line, replay: q.get("replay") === "1" } };
}

export function eventSourceLink(net: number, source: Schemas["MessagesSource"], fallback: number): string | undefined {
 const dataset = source.dataset_id || fallback;
 if (![net, dataset, source.ordinal].every(n => Number.isSafeInteger(n) && n > 0) || !identifier.test(source.input) || source.kind !== "event" && source.kind !== "log") return undefined;
 const q = new URLSearchParams({ dataset: String(dataset), input: source.input, line: String(source.ordinal), replay: "1" });
 return `#/networks/${net}/events?${q}`;
}
