import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { TimerEvidence } from "./views/TimerEvidence";

describe("measured timer evidence",()=>{
 it("preserves large coordinates and separates operation time from arm entry",()=>{
  const html=renderToStaticMarkup(<TimerEvidence operation={{sequence:"9007199254740993",action:"queued",source:"core",output:"3",arm_engine_run:"2",arm_step:"9007199254740994",arm_output:"3",arm_entry_mono_ns:"0",deadline_mono_ns:"12",cancel_kinds:[],decode:"complete",timer:"retry",generation:"7",height:"9007199254740995",round:"1",timeout_sha256:"a".repeat(64)}}/>);
  expect(html).toContain("9007199254740993");expect(html).toContain("9007199254740994");expect(html).toContain("9007199254740995");expect(html).toContain("separately from core entry and completion");expect(html).toContain("Payload bytes remain in the original source");
 });
 it("explains cancellation without hiding queued expiry",()=>{
  const html=renderToStaticMarkup(<TimerEvidence operation={{sequence:"3",action:"cancel",source:"lifecycle",output:"0",arm_engine_run:"0",arm_step:"0",arm_output:"0",arm_entry_mono_ns:"0",deadline_mono_ns:"0",cancel_kinds:["round","retry","future"],decode:"not_applicable"}}/>);
  expect(html).toContain("A queued expiry survives cancellation");expect(html).toContain("Zero denotes a lifecycle");expect(html).toContain("no single arm source");expect(html).not.toContain("Original arm:");
  expect(renderToStaticMarkup(<TimerEvidence operation={null}/>)).toBe("");
 });
 it("separates the local proposal wait and retains four cancellation kinds",()=>{
  const base={sequence:"1",source:"core",output:"1",arm_engine_run:"1",arm_step:"1",arm_output:"1",arm_entry_mono_ns:"0",deadline_mono_ns:"12",cancel_kinds:[],decode:"complete",timer:"round_proposal",generation:"9007199254740993",height:"9007199254740994",round:"3",timeout_sha256:"a".repeat(64)};
  const html=renderToStaticMarkup(<TimerEvidence operation={{...base,action:"arm"}}/>);
  expect(html).toContain("Local proposal wait");expect(html).toContain("matching expiry rechecks the current local candidate");expect(html).toContain("does not represent a received message");expect(html).toContain("9007199254740993");expect(html).toContain("9007199254740994");
  const cancelled=renderToStaticMarkup(<TimerEvidence operation={{sequence:"2",action:"cancel",source:"core",output:"2",arm_engine_run:"0",arm_step:"0",arm_output:"0",arm_entry_mono_ns:"0",deadline_mono_ns:"0",cancel_kinds:["round","retry","future","round_proposal"],decode:"not_applicable"}}/>);
  expect(cancelled).toContain("round, retry, future, Local proposal wait");expect(cancelled).toContain("A queued expiry survives cancellation");
 });
});
