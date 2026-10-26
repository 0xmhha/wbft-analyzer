import {expect,it} from "vitest";
import {renderToStaticMarkup} from "react-dom/server";
import {bandCoordinate,ObservationBandPanel,ObservationBands} from "./views/ObservationBands";
import {parseRoute} from "./App";
import type {Schemas} from "./api/client";

const hash="0x"+"1".repeat(64);
const sample=()=>({schema:"wbft-analyzer-observation-band/1",source_sha256:"a".repeat(64),source_scope:"node_reported",report:{schema:"wbft-observation-band-rpc/1",status:"AVAILABLE",chain_id:"9912",genesis_hash:hash,core_version:"synthetic",verification_scope:"node_adopted_observation_state",diagnostic:{schema:"wbft-observation-band/1",view:"recent_preview",carrier_hash:hash,carrier_height:"9",state_root:hash,observation_policy:hash,retention:"3",from:"5",through:"7",address:"0x"+"2".repeat(40),eligible:"3",observed_prepare:"3",observed_commit:"3",minimum:"3",numerator:"4",denominator:"5",history_status:"SUFFICIENT_HISTORY",observed_band:"IN_OBSERVED_BAND"}},arithmetic:{history_status:"SUFFICIENT_HISTORY",observed_band:"IN_OBSERVED_BAND",matches_reported:true}});
const render=(value:unknown)=>renderToStaticMarkup(<ObservationBandPanel inspection={value as Schemas["ObservationBandInspection"]}/>);

it("keeps node provenance separate from the count check",()=>{
 const html=render(sample());expect(html).toContain("Node reported");expect(html).toContain("not independently verified here");expect(html).toContain("Prepare: 3 of 3");expect(html).toContain("Commit: 3 of 3");expect(html).toContain("Within requested band");expect(html).toContain("Reported arithmetic matches");expect(html).not.toContain(">PASS<");
});
it("does not turn missing samples or unavailable data into zero scores",()=>{
 const empty=sample();empty.report.diagnostic.eligible="0";empty.report.diagnostic.observed_prepare="0";empty.report.diagnostic.observed_commit="0";empty.report.diagnostic.history_status="NO_HISTORY";
 const value={...empty,report:{...empty.report,diagnostic:{...empty.report.diagnostic,observed_band:null}},arithmetic:{history_status:"NO_HISTORY",observed_band:null,matches_reported:true}};
 const html=render(value);expect(html).toContain("No history");expect(html).toContain("Band unclassified");expect(html).toContain("No ratio without eligible opportunities");expect(html).not.toContain("0.00% observed");
 const unavailable=render({...sample(),report:{schema:"wbft-observation-band-rpc/1",status:"UNAVAILABLE",reason:"observation_tip_not_current"},arithmetic:null});expect(unavailable).toContain("No numeric observation is available");expect(unavailable).not.toContain("<svg");
});
it("shows discrepancies without declaring a consensus failure",()=>{
 const s=sample();s.report.diagnostic.observed_commit="2";s.arithmetic.observed_band="BELOW_OBSERVED_BAND";s.arithmetic.matches_reported=false;
 const html=render(s);expect(html).toContain("Reported classification differs");expect(html).toContain("Below requested band");expect(html).not.toContain(">FAIL<");
});
it("preserves full decimal heights and bounded display coordinates",()=>{
 const s=sample(),full=1n<<128n;s.report.diagnostic.carrier_height=full.toString();expect(render(s)).toContain(full.toString());expect(bandCoordinate(full.toString(),full.toString())).toBe(1000);expect(bandCoordinate("0","0")).toBeNull();expect(bandCoordinate("4","3")).toBeNull();expect(bandCoordinate("01","3")).toBeNull();
});
it("offers a network-independent file workflow",()=>{
 expect(parseRoute("#/observation-bands")).toEqual({view:"observation-bands"});const html=renderToStaticMarkup(<ObservationBands onAuth={()=>{}}/>);expect(html).toContain('type="file"');expect(html).toContain("Check arithmetic");expect(html).toContain("UTF-8 JSON");
});
