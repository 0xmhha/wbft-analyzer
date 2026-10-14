import type { Schemas } from "./api/client";
export type LogEvent = Schemas["StoreLogEvent"];

export function eventKey(e: LogEvent): string { return `${e.input}:${e.line}`; }
export function field(e: LogEvent, key: string): string {
  const f = e.fields as Record<string, unknown> | null;
  const v = f?.[key];
  return typeof v === "string" || typeof v === "number" || typeof v === "boolean" ? String(v) : "";
}
/** Coordinates use wall time only; full height and round never become JS numbers. */
export function eventLayout(events: LogEvent[], nodes: string[], from: string, to: string) {
  const a = Date.parse(from), b = Date.parse(to), span = Math.max(1, b - a);
  return events.map((event) => ({ event, x: 140 + 820 * Math.max(0, Math.min(1, (Date.parse(event.t_wall) - a) / span)), y: 52 + 58 * nodes.indexOf(event.node) })).filter((p) => nodes.includes(p.event.node));
}
export function eventClass(e: LogEvent): string {
  if (e.kind === "TIMER_FIRE") return "event-timeout";
  if (e.kind === "ROUND_ENTER") return "event-round";
  if (e.kind === "NEW_HEAD") return "event-head";
  if (e.kind === "QUORUM") return "event-quorum";
  if (["BUILD_HANDOVER","BUILD_STARTED","BUILD_FINISHED"].includes(e.kind)) return "event-build";
  if (e.kind === "SEND") return "event-send";
  return "event-other";
}
export function timeWindow(anchor: number, span: number, bounds: { from_t: string | null; to_t: string | null }) {
  const min = Date.parse(bounds.from_t || ""), max = Date.parse(bounds.to_t || "");
  const a = Math.max(min, Math.min(anchor, Math.max(min, max - span)));
  return { from_t: new Date(a).toISOString(), to_t: new Date(Math.min(max, a + span)).toISOString() };
}
