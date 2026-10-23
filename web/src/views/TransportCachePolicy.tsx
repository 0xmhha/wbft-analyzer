import type { LogEvent } from "../events";
import { transportCacheDeclaration } from "../transportCache";

export function TransportCachePolicy({ event }: { event: LogEvent }) {
  if (event.kind !== "NODE_START") return null;
  const fields = (event.fields || {}) as Record<string, unknown>;
  if (!Object.keys(fields).some(key => key.startsWith("transport_cache_"))) return null;
  const declaration = transportCacheDeclaration(fields);
  if (!declaration) return <section className="transport-cache-policy" aria-label="Cache policy declaration"><h3>Cache policy declaration unavailable</h3><p>The startup fields are incomplete or unsupported. Cache registration rules remain unknown.</p></section>;
  return <section className="transport-cache-policy" aria-label="Configured cache gates">
    <h3>Configured cache gates</h3>
    <p><strong>{declaration.active ? "Active at startup" : "Inactive at startup"}</strong> · accepted input / completed local write</p>
    <div className="transport-cache-flows">
      <div><h4>Receive</h4><ol aria-label="Configured receive gate"><li>Received input</li><li>Direct core ACCEPT</li><li>Known entry</li></ol></div>
      <div><h4>Send</h4><ol aria-label="Configured send gate"><li>Queued request</li><li>Successful local write</li><li>Peer recent entry</li></ol></div>
    </div>
    <p>This startup record describes the configured gates. It contains no measured cache transitions or remote delivery receipts.</p>
    <div className="table-scroll"><table><caption>Pending entry limits</caption><thead><tr><th>Work</th><th>Total</th><th>Per peer</th></tr></thead><tbody>
      <tr><th>Receive checks</th><td className="mono">{declaration.limits.receive_pending}</td><td className="mono">{declaration.limits.receive_per_peer}</td></tr>
      <tr><th>Local writes</th><td className="mono">{declaration.limits.write_pending}</td><td className="mono">{declaration.limits.write_per_peer}</td></tr>
    </tbody></table></div>
    <p className="muted">These counts do not bound heap, payload bytes or transport duration. Queue admission does not establish a successful write.</p>
  </section>;
}
