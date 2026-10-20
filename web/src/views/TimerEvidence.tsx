import type { Schemas } from "../api/client";

type Operation = NonNullable<Schemas["MessagesRecord"]["timer_operation"]>;
export function TimerEvidence({operation}:{operation?:Operation|null}) {
 if(!operation)return null;
 return <section aria-label="Measured timer operation"><h3>Measured timer operation</h3>
  <p>{operation.action} · operation sequence <code>{operation.sequence}</code> · source {operation.source} · output <code>{operation.output}</code></p>
  {operation.timer&&<p>{operation.timer==="round_proposal"?"Local proposal wait":operation.timer} · generation <code>{operation.generation}</code> · full height / round <code>{operation.height} / {operation.round}</code></p>}
  {operation.timer==="round_proposal"&&<p>A matching expiry rechecks the current local candidate. This wait does not represent a received message.</p>}
  {operation.cancel_kinds.length>0&&<p>Cancellation request: {operation.cancel_kinds.map(kind=>kind==="round_proposal"?"Local proposal wait":kind).join(", ")}. A queued expiry survives cancellation.</p>}
  {operation.arm_engine_run!=="0"?<><p>Original arm: engine <code>{operation.arm_engine_run}</code> / step <code>{operation.arm_step}</code> / output <code>{operation.arm_output}</code>.</p>
  <p>Arm entry <code>{operation.arm_entry_mono_ns}</code> ns · deadline <code>{operation.deadline_mono_ns}</code> ns. The source record timestamp measures this operation, separately from core entry and completion.</p></>:<p>This operation has no single arm source. Its record timestamp measures the scheduler operation.</p>}
  <p>Output indices are one-based. Zero denotes a lifecycle, dequeue or restoration operation. Callback cause refers to its original arm.</p>
  {operation.timeout_sha256&&<p>Timeout context SHA256 <code>{operation.timeout_sha256}</code> · decode {operation.decode}. Payload bytes remain in the original source.</p>}
 </section>;
}
