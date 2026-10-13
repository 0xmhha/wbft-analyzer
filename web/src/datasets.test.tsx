import {renderToStaticMarkup} from "react-dom/server";
import {describe,it,expect} from "vitest";
import {parseRoute} from "./App";
import {InputStorageSummary} from "./views/Datasets";
describe("dataset input ownership",()=>{
 it("keeps restored and shared objects distinct from owned bytes",()=>{
 const foreign=renderToStaticMarkup(<InputStorageSummary storage={{state:"foreign",input_files:0,input_bytes:0}}/>);expect(foreign).toContain("another database");expect(foreign).toContain("Copy and verify");expect(foreign).not.toContain("No retained input bytes");
 const shared=renderToStaticMarkup(<InputStorageSummary storage={{state:"unmanaged",input_files:0,input_bytes:0}}/>);expect(shared).toContain("shared storage");
 const owned=renderToStaticMarkup(<InputStorageSummary storage={{state:"owned",input_files:2,input_bytes:1000}}/>);expect(owned).toContain("2 owned input objects");
 });
 it("offers a truthful retry state and scopes management to a network",()=>{
 expect(parseRoute("#/networks/7/datasets")).toEqual({view:"datasets",net:7});expect(parseRoute("#/networks/0/datasets")).toEqual({view:"overview"});
 expect(renderToStaticMarkup(<InputStorageSummary storage={{state:"deleting",input_files:3,input_bytes:1000}}/>)).toContain("cleanup is pending");
 });
});
