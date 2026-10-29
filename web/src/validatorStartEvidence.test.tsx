import {expect,it} from "vitest";
import {renderToStaticMarkup} from "react-dom/server";
import {TimerEvidence} from "./views/TimerEvidence";

it("separates validator startup wait and preserves five cancellation kinds",()=>{
 const base={sequence:"1",source:"core",output:"1",arm_engine_run:"1",arm_step:"1",arm_output:"1",arm_entry_mono_ns:"0",deadline_mono_ns:"1000000000",cancel_kinds:[],decode:"complete",timer:"validator_start",generation:"9007199254740993",height:"9007199254740994",round:"3",timeout_sha256:"a".repeat(64)};
 const html=renderToStaticMarkup(<TimerEvidence operation={{...base,action:"arm"}}/>);
 expect(html).toContain("Validator startup wait");expect(html).toContain("Production stays paused until that lookup is available");expect(html).toContain("9007199254740993");expect(html).toContain("9007199254740994");
 const cancelled=renderToStaticMarkup(<TimerEvidence operation={{sequence:"2",action:"cancel",source:"core",output:"2",arm_engine_run:"0",arm_step:"0",arm_output:"0",arm_entry_mono_ns:"0",deadline_mono_ns:"0",cancel_kinds:["round","retry","future","round_proposal","validator_start"],decode:"not_applicable"}}/>);
 expect(cancelled).toContain("round, retry, future, Local proposal wait, Validator startup wait");expect(cancelled).toContain("A queued expiry survives cancellation");
});
