// The geometry of the observation trend view: a line of rates over report
// time, with the thresholds of the absolute rules as horizontal lines
// labelled where they end (no legend).
import { extent, max } from "d3-array";
import { scaleLinear, scaleUtc } from "d3-scale";
import { line } from "d3-shape";
import type { Schemas } from "./api/client";

export interface Plot {
  path: string;
  dots: { x: number; y: number; at: string; rate: number }[];
  thresholds: { y: number; label: string }[];
  xTicks: { x: number; label: string }[];
  yTicks: { y: number; label: string }[];
}

export const margin = { top: 12, right: 140, bottom: 28, left: 56 };

/** Lays out points and rules in a width x height box. */
export function plot(points: Schemas["TrendPoint"][], rules: Schemas["AlertRule"][], width: number, height: number): Plot {
  const pts = points.map((p) => ({ ...p, t: new Date(p.at) })).sort((a, b) => a.t.getTime() - b.t.getTime());
  const absolute = rules.filter((r) => r.mode === "absolute");
  const [t0, t1] = extent(pts, (p) => p.t);
  const x = scaleUtc()
    .domain(t0 && t1 ? [t0, t1] : [new Date(0), new Date(1)])
    .range([margin.left, width - margin.right]);
  const top = Math.max(max(pts, (p) => p.rate) ?? 0, max(absolute, (r) => r.threshold) ?? 0) || 1;
  const y = scaleLinear()
    .domain([0, top])
    .nice()
    .range([height - margin.bottom, margin.top]);
  const dots = pts.map((p) => ({ x: x(p.t), y: y(p.rate), at: p.at, rate: p.rate }));
  return {
    path:
      line<{ x: number; y: number }>()
        .x((d) => d.x)
        .y((d) => d.y)(dots) ?? "",
    dots,
    thresholds: absolute.map((r) => ({ y: y(r.threshold), label: `rule ${r.id ?? ""}: rate > ${r.threshold}` })),
    xTicks: x.ticks(5).map((t) => ({ x: x(t), label: t.toISOString().slice(0, 16).replace("T", " ") })),
    yTicks: y.ticks(4).map((v) => ({ y: y(v), label: String(v) })),
  };
}
