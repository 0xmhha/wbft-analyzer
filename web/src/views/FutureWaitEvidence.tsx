import type { LogEvent } from "../events";

function duration(fields: Record<string, unknown>, key: string): string {
 const value=fields[key];
 if(typeof value!=="string" || !/^[1-9][0-9]*$/.test(value) || value.length>19)return "unknown";
 return BigInt(value)<=9223372036854775807n?value:"unknown";
}

export function FutureWaitEvidence({event}:{event:LogEvent}) {
 const fields=(event.fields || {}) as Record<string, unknown>;
 if(event.kind!=="HEALTH" || fields.what!=="future_proposal_wait_exceeded")return null;
 const origin=fields.proposal_origin==="preprepare"?"Received proposal":fields.proposal_origin==="local_reproposal"?"Local prepared candidate":"Proposal origin unavailable";
 return <section className="future-wait-evidence" aria-label="Recorded proposal wait rejection">
  <h3>Proposal wait exceeded the local limit</h3>
  <dl><dt>Proposal</dt><dd>{origin}</dd><dt>Requested wait</dt><dd><code>{duration(fields,"wait_ns")}</code> ns</dd><dt>Round timeout limit</dt><dd><code>{duration(fields,"limit_ns")}</code> ns</dd></dl>
  <p>These recorded lengths do not measure elapsed or remaining time. Missing values remain unknown.</p>
 </section>;
}
