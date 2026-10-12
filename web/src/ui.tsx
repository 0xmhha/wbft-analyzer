// Shared pieces: the glyph of an encoding, loading and error states.
import { useEffect, useState } from "react";
import { ApiError } from "./api/client";
import type { Encoding } from "./visual";

/** The shape of an encoding, size px, coloured by its class. */
export function Glyph({ enc, size = 12 }: { enc: Encoding; size?: number }) {
  const h = size / 2;
  return (
    <svg className={`glyph ${enc.className}`} width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={enc.label}>
      <title>{enc.label}</title>
      {enc.glyph === "disc" && <circle cx={h} cy={h} r={h - 1} />}
      {enc.glyph === "ring" && <circle cx={h} cy={h} r={h - 2} className="ring" />}
      {enc.glyph === "half-disc" && <>
        <path d={`M${h} 2A${h - 2} ${h - 2} 0 0 0 ${h} ${size - 2}Z`} className="half" />
        <circle cx={h} cy={h} r={h - 2} className="ring" />
      </>}
      {enc.glyph === "cross" && <path d={`M2 2L${size - 2} ${size - 2}M${size - 2} 2L2 ${size - 2}`} className="stroke" />}
      {enc.glyph === "hatch" && <rect x={0.5} y={0.5} width={size - 1} height={size - 1} className="hatch" />}
    </svg>
  );
}

/** The glyph and its name, for labelling marks directly. */
export function Labelled({ enc }: { enc: Encoding }) {
  return (
    <span className="labelled">
      <Glyph enc={enc} /> {enc.label}
    </span>
  );
}

export type Load<T> = { state: "loading" } | { state: "error"; error: Error } | { state: "done"; data: T };

/** Runs load whenever deps change; a result that arrives late is dropped. */
export function useLoad<T>(load: () => Promise<T>, deps: unknown[]): Load<T> {
  const [s, set] = useState<Load<T>>({ state: "loading" });
  useEffect(() => {
    let live = true;
    set({ state: "loading" });
    load().then(
      (data) => live && set({ state: "done", data }),
      (error: Error) => live && set({ state: "error", error }),
    );
    return () => {
      live = false;
    };
  }, deps);
  return s;
}

/** Shows a load that is not done; null when it is. A 401 asks for the token. */
export function Pending({ load, onAuth }: { load: Load<unknown>; onAuth: () => void }) {
  const needsToken = load.state === "error" && load.error instanceof ApiError && load.error.status === 401;
  useEffect(() => {
    if (needsToken) onAuth();
  }, [needsToken, onAuth]);
  if (load.state === "loading") return <p className="muted">Loading…</p>;
  if (load.state === "error") {
    return <p className="error">{needsToken ? "This server needs a token." : load.error.message}</p>;
  }
  return null;
}
