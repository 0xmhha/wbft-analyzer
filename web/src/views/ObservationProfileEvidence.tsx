import type { Schemas } from "../api/client";

type Profile = NonNullable<Schemas["MessagesRecord"]["observation"]>;

export function ObservationProfileEvidence({profile}: {profile?: Profile | null}) {
 if (!profile) return null;
 return <section aria-label="Recorded participation observation policy" style={{overflowWrap:"anywhere"}}>
  <h3>Recent participation observation policy</h3>
  <p>Profile {profile.version} · recorded retention H {profile.retention} matured blocks · activation {profile.activation} · proof window {profile.window}.</p>
  <p className="mono">Policy digest {profile.policy_digest}</p>
  <p>Replay bound {profile.replay_headers} headers · historical walk bound {profile.history_walk} headers.</p>
  <p>{profile.checkpoint_status === "recorded_requires_chain"
   ? "A writer-start checkpoint was recorded. Original reproduction requires its matching header from the independent canonical chain."
   : "This writer recorded no observation checkpoint. Recovery requires an activation parent within the replay bound."}</p>
  <details><summary>Recorded policy limits</summary><table><thead><tr><th>Limit</th><th>Exact value</th></tr></thead><tbody>{Object.entries(profile.limits).map(([name,value])=><tr key={name}><th>{name.replaceAll("_"," ")}</th><td className="mono">{value}</td></tr>)}</tbody></table></details>
  <p>These fields describe an observation policy. Economic participation weights remain a separate policy.</p>
 </section>;
}
