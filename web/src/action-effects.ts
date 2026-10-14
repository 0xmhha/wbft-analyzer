import type { Schemas } from "./api/client";
type Action=Schemas["WhatifAction"];
type Step=Schemas["WhatifStep"];

export function networkActions(actions:Action[]):Action[] {
 return actions.filter(a=>a.kind==="broadcast"||a.kind==="relay");
}
// Timer fingerprints cannot establish a network change. Compare the ordered
// network intents, and require byte evidence before claiming equal bytes.
export function networkComparison(step:Pick<Step,"output_actions"|"recorded_output_actions">&{generated?:boolean}):"unavailable"|"none"|"same"|"changed"|"unknown"|"generated" {
 if(step.output_actions==null||step.recorded_output_actions==null)return "unavailable";
 const current=networkActions(step.output_actions),original=networkActions(step.recorded_output_actions);
 if(!current.length&&!original.length)return "none";
 if(step.generated)return "generated";
 if(current.length!==original.length)return "changed";
 if([...current,...original].some(a=>a.recipient_evidence==="unknown"||a.payload_evidence==="unsigned_request"))return "unknown";
 const identity=(a:Action)=>JSON.stringify([a.kind,a.code,a.payload_evidence,a.payload_sha256??null,a.eligible_recipients]);
 return current.every((a,i)=>original[i]!=null&&identity(a)===identity(original[i]))?"same":"changed";
}

export const networkLabels={
 generated:"Generated network intent has no original slot comparison. Recorded signing producers are shown separately; delivery is unknown.",
 unavailable:"Output evidence unavailable for this stored execution.",
 none:"No network output intent in this execution or its original slot.",
 same:"Same recorded network bytes and recipient intent in this execution. Delivery remains unproved.",
 changed:"Network output intent differs in this execution. Removed original intent and new intent are shown separately; changed delivery is unknown.",
 unknown:"Network comparison is unknown: unsigned bytes or recipient membership evidence is missing."
};
