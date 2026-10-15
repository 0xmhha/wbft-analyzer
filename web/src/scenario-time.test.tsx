import { describe,expect,it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { Schemas } from "./api/client";
import { ScenarioTimeEvidence } from "./views/ScenarioTimeEvidence";

function fixture():Schemas["ScenarioHeaderTimeComparison"]{
 const exact:Schemas["ScenarioConditionalProbability"]={method:"fixed_margins_probability_mass/exact",p:.001,exact:true,underflow:false,samples:5,seed:"1",lower:.001,upper:.001,error_probability:0,log_mass_tolerance:1e-9};
 return {method:"wbft-header-interval-baseline/1",status:"distinguishable",alpha:.01,from:"9007199254740993",to:"9007199254740994",recorded_runs:1,simulated_runs:2,recorded:[{run:"recorded-1",samples:2,counts:[{seconds:"18446744073709551615",count:2}]}],simulated:[],recorded_homogeneity:exact,simulated_homogeneity:{...exact,method:"fixed_margins_probability_mass/monte_carlo",exact:false,p:.4,lower:.39,upper:.41,error_probability:1e-6,seed:"18446744073709551615"},comparison:exact,maximum_cdf_difference:.5,numerical_error_probability:1e-6,assumptions:["non_rejection_does_not_prove_exact_or_physical_equivalence"]};
}

describe("header interval time evidence",()=>{
 it("distinguishes a rejected distribution and shows numerical uncertainty and full integer categories",()=>{
  const html=renderToStaticMarkup(<ScenarioTimeEvidence timing={fixture()} check="failed"/>);
  expect(html).toContain("Header interval baseline: failed");expect(html).toContain("scenario-unproved");expect(html).toContain("significance level α = 0.01");
  expect(html).toContain("9007199254740993");expect(html).toContain("18446744073709551615");expect(html).toContain("Complete interval histograms");
  expect(html).toContain("Numerical tail-probability bounds: [0.39, 0.41]");expect(html).toContain("not physical timing uncertainty");expect(html).toContain("Recorded versus baseline intervals");expect(html).toContain("Non-rejection does not establish");
 });
 it("keeps historical missing criteria separate from pending and precision-limited checks",()=>{
  const historical=renderToStaticMarkup(<ScenarioTimeEvidence check="threshold_unconfigured"/>);
  expect(historical).toContain("criteria unavailable for this stored experiment");expect(historical).not.toContain("significance level");
  expect(renderToStaticMarkup(<ScenarioTimeEvidence check="pending"/>)).toContain("check pending");
  const timing=fixture();timing.status="precision_limited";timing.issue="interval_run_homogeneity_precision_limited";timing.comparison=null;
  const html=renderToStaticMarkup(<ScenarioTimeEvidence timing={timing} check="unproved"/>);
  expect(html).toContain("Header interval baseline: unproved");expect(html).toContain(timing.issue);expect(html).toContain("Recorded versus baseline intervals: unavailable");expect(html).not.toContain("baseline: passed");
 });
 it("does not display exact floating-point underflow as a Monte Carlo zero",()=>{
  const timing=fixture();timing.comparison={...timing.comparison!,p:0,underflow:true,log_p:-1000};
  const html=renderToStaticMarkup(<ScenarioTimeEvidence timing={timing} check="failed"/>);
  expect(html).toContain("p: below floating-point range");expect(html).toContain("log(p): -1000");
 });
});
