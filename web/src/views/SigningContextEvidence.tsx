import type { Schemas } from "../api/client";

export function SigningContextEvidence({record}:{record:Schemas["MessagesRecord"]}) {
 const profile=record.signing_profile;
 if(!profile)return <p>Legacy signature interpretation. No chain domain declaration is attached to this record.</p>;
 return <section aria-label="Recorded signing context"><h3>Recorded chain signing context</h3><p>Domain version {profile.version} · activation height {profile.activation}. Each round-change message uses its own full height. This declaration does not independently authenticate the genesis or validator membership.</p><p className="mono">Declaration SHA256 {profile.sha256}</p></section>;
}
