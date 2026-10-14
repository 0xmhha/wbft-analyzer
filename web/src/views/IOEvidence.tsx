import type { Schemas } from "../api/client";

export function IOEvidence({interval}:{interval?:Schemas["MessagesIOInterval"]|null}) {
 return <section aria-label="Transport I/O evidence"><h3>Measured transport I/O</h3>{interval?<><dl><dt>Start wall time</dt><dd>{interval.start_wall}</dd><dt>End wall time</dt><dd>{interval.end_wall}</dd><dt>Start monotonic ns</dt><dd>{interval.start_mono_ns}</dd><dt>End monotonic ns</dt><dd>{interval.end_mono_ns}</dd></dl><p>Endpoints bracket the recorded I/O operation. The frame callback time remains separate. Reads may include waiting. Wall-clock regressions are preserved; these endpoints do not establish corrected latency or delivery coverage.</p></>:<p>I/O interval unavailable. The callback timestamp does not supply missing endpoints.</p>}</section>;
}
