import type { Schemas } from "./api/client";
type Step=Schemas["WhatifStep"];
type Summary=Schemas["WhatifNetworkSummary"];

// Go emits UTC RFC3339Nano. Keep its fractional nanoseconds instead of
// rounding a boundary to browser Date milliseconds.
export function wallNanoseconds(value:string):bigint|null {
 const match=/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$/.exec(value);
 if(!match?.[1])return null;
 const millis=Date.parse(match[1]+"Z");
 if(!Number.isSafeInteger(millis)||new Date(millis).toISOString().slice(0,19)!==match[1])return null;
 return BigInt(millis)*1_000_000n+BigInt((match[2]??"").padEnd(9,"0"));
}

export function impactRegion(step:Step,summary:Summary|null):"unproved"|"potential_original_influence"|"unaligned"|"before"|"unavailable" {
 if(summary==null)return "unavailable";
 const first=summary.first_unproved_output;
 if(first&&BigInt(step.execution_step)>=BigInt(first.execution_step))return "unproved";
 if(summary.status!=="bounded_original_delivery")return summary.status==="unchanged_under_model"?"before":"unavailable";
 const from=summary.first_observed_removed_arrival?.from_t_wall;
 if(!from||!step.source_entry_t_wall)return "unaligned";
 const at=wallNanoseconds(step.source_entry_t_wall),lower=wallNanoseconds(from);
 if(at==null||lower==null)return "unaligned";
 const uncertainty=BigInt(summary.scope.skew_ms??0)*1_000_000n;
 return at+uncertainty>=lower?"potential_original_influence":"before";
}
