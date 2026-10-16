import {expect,it} from "vitest";
import {governanceCollections,governanceIndex,governancePositions,governancePhase,governanceOutcome,governancePointer,governanceProposalStatus} from "./governance";

it("keeps adjacent uint64 maxima distinct when placing marks",()=>{
 expect(governancePositions(["0xfffffffffffffffd","0xfffffffffffffffe","0xffffffffffffffff"])).toEqual([60,420,780]);
 expect(governancePositions(["0x1","0xffffffffffffffff"])).toEqual([60,780]);
 expect(governancePositions(["0x0","0x0"])).toEqual([420,420]);
 expect(governancePositions(["0x10000000000000000"])).toBeNull();
 expect(governancePositions(["0x01"])).toBeNull();
 expect(governanceIndex("0xffffffffffffffff")).toContain("18446744073709551615");
});
it("retains attempts and unknown outcomes without treating source claims as verification",()=>{
 expect(governanceOutcome({result:"revert",effective:false,view:false}).label).toBe("failed attempt");
 expect(governanceOutcome({result:"unknown",effective:true,view:false}).kind).toBe("unknown");
 expect(governanceOutcome({result:"success",effective:false,view:false}).kind).toBe("attempt");
 expect(governanceOutcome({result:"success",effective:true,view:true}).kind).toBe("attempt");
 expect(governanceOutcome({result:"success",effective:true,view:false}).label).toBe("effective (reported)");
 expect(governancePhase("approveProposal(uint256)")).toBe("vote");
 expect(governancePhase("executeWithFailure(uint256)")).toBe("execution");
 expect(governancePhase("unknown")).toBe("unknown");
 expect(governanceProposalStatus(3)).toBe("executed");
 expect(governanceProposalStatus(255)).toBe("unknown (255)");
});
it("keeps proposal history and validator-change operations under their own request",()=>{
 expect(governanceCollections("wbft_govProposal")).toEqual(["proposals","operations"]);
 expect(governanceCollections("wbft_validatorChanges")).toEqual(["changes","operations"]);
 expect(governanceCollections("wbft_nodeInfo")).toEqual([]);
 const source={data:{ops:[{number:"0x1",executing_proposal_id:null}]}};
 expect(governancePointer(source,"/data/ops/0")).toEqual(source.data.ops[0]);
 expect(governancePointer(source,"/data/ops/0/executing_proposal_id")).toBeNull();
 expect(governancePointer(source,"/data/__proto__")).toBeUndefined();
 expect(governancePointer(source,"/data/ops/2")).toBeUndefined();
});
