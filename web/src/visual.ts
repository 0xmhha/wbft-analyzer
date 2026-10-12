// The visual rules shared by every view (replay.md 6): a value is told by
// colour and shape together; an unknown value is hatched, never blank,
// since blank reads as "none".

export type Glyph = "disc" | "half-disc" | "cross" | "hatch" | "ring";

export interface Encoding {
  label: string;
  className: string; // colour, in style.css
  glyph: Glyph;
}

/** The inspector's verdicts (wbft-inspector internal/verdict). */
export const verdicts: Record<string, Encoding> = {
  PASS: { label: "pass", className: "v-pass", glyph: "disc" },
  FAIL: { label: "fail", className: "v-fail", glyph: "cross" },
  CANNOT_DECIDE: { label: "cannot decide", className: "v-unknown", glyph: "hatch" },
  NOT_RUN: { label: "not run", className: "v-notrun", glyph: "ring" },
};

/** A requirement a report does not list: not judged there. */
export const absent: Encoding = { label: "not in report", className: "v-absent", glyph: "hatch" };

/** Passed instances mixed with undecided ones still have an undecided verdict. */
export const partlyPassed: Encoding = { label: "partly passed", className: "v-partly", glyph: "half-disc" };

/** The encoding of a verdict; a verdict this build does not know is drawn as unknown. */
export function verdictEncoding(v: string | undefined, coverage?: unknown): Encoding {
  if (v === undefined) return absent;
  if (v === "CANNOT_DECIDE" && coverage !== null && typeof coverage === "object") {
    const c = coverage as Record<string, unknown>;
    if (typeof c.pass === "number" && Number.isSafeInteger(c.pass) && c.pass > 0 &&
        c.fail === 0 && typeof c.cannot_decide === "number" && Number.isSafeInteger(c.cannot_decide) && c.cannot_decide > 0) {
      return partlyPassed;
    }
  }
  return verdicts[v] ?? { label: v.toLowerCase(), className: "v-unknown", glyph: "hatch" };
}

/** The alert states of a rule (design.md 6.7). */
export const alertStates: Record<string, Encoding> = {
  pending: { label: "pending: too few points", className: "a-pending", glyph: "hatch" },
  firing: { label: "firing", className: "a-firing", glyph: "cross" },
  resolved: { label: "resolved", className: "a-resolved", glyph: "disc" },
};
