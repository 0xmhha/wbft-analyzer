import { describe, expect, it } from "vitest";
import { margin, plot } from "./trend";

const point = (at: string, rate: number) => ({ report: at, at, kind: "late_seal", node: "", rate });

describe("plot", () => {
  it("orders points by time, spans the box, and draws absolute thresholds only", () => {
    const p = plot(
      [point("2026-10-12T00:02:00Z", 0.02), point("2026-10-12T00:00:00Z", 0), point("2026-10-12T00:01:00Z", 0.04)],
      [
        { id: 1, kind: "late_seal", node: "", window: 3, baseline: 0, mode: "absolute", threshold: 0.03, webhook: "" },
        { id: 2, kind: "late_seal", node: "", window: 1, baseline: 3, mode: "relative", threshold: 2, webhook: "" },
      ],
      640,
      240,
    );
    expect(p.dots.map((d) => d.rate)).toEqual([0, 0.04, 0.02]);
    expect(p.dots[0]?.x).toBe(margin.left);
    expect(p.dots[2]?.x).toBe(640 - margin.right);
    expect(p.dots[0]?.y).toBe(240 - margin.bottom); // rate 0 on the axis
    expect(p.thresholds).toHaveLength(1);
    expect(p.thresholds[0]?.label).toBe("rule 1: rate > 0.03");
    expect(p.path.startsWith("M")).toBe(true);
  });

  it("draws nothing without points", () => {
    const p = plot([], [], 640, 240);
    expect(p.dots).toEqual([]);
    expect(p.path).toBe("");
  });
});
