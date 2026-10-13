import {describe,it,expect} from "vitest";
import {headerEvidenceFocus,parseRoute} from "./App";
describe("canonical header evidence routing",()=>{
 it("keeps the canonical uint64 index independent of full height",()=>{
  expect(headerEvidenceFocus("index=18446744073709551615&dataset=8&node=observer")).toEqual({headerFocus:{index:"18446744073709551615",dataset:8,node:"observer"}});
  expect(parseRoute("#/networks/3/headers?index=1&dataset=8&node=observer")).toEqual({view:"headers",net:3,headerFocus:{index:"1",dataset:8,node:"observer"}});
  expect(headerEvidenceFocus("index=0")).toEqual({headerFocus:{index:"0",dataset:0,node:""}});
 });
 it("refuses invalid or partial source pointers",()=>{
  for(const q of ["index=18446744073709551616","index=01","index=1&dataset=8","index=1&node=observer","index=1&dataset=9007199254740992&node=observer","index=1&index=2","index=1&secret=value"]){expect(headerEvidenceFocus(q).sourceError).toBeTruthy()}
 });
});
