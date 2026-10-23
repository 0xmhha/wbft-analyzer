import type { Schemas } from "../api/client";

type Evidence = NonNullable<Schemas["MessagesRecord"]["deferred_origin"]>;

export function DeferredEvidence({evidence, writer}: {evidence?: Evidence | null; writer: string}) {
 if (!evidence) return null;
 const origin = evidence.origin;
 return <section aria-label="Deferred message source">
  <strong>Deferred message source: {evidence.status}</strong>
  <p>Original writer {origin.writer_run || "unavailable"} · capture {origin.capture_id === "0" ? "unavailable" : origin.capture_id}</p>
  {evidence.status === "verified"
   ? <p>Original receipt {evidence.receipt_mono_ns} ns in writer {origin.writer_run}.
      {origin.writer_run !== writer && " This uses another writer clock; elapsed time is unavailable."}</p>
   : <p>Physical source unavailable: {evidence.reason || "unknown"}. Inline functional replay remains independent of capture retention.</p>}
 </section>;
}
