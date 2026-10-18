package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/systemcontracts"
)

// Error signatures are the public wire contract. No arbitrary revert message
// or argument is retained; canonical ABI decoding only yields a known name.
const baseErrors = "AlreadyAMember AlreadyApproved DuplicateMember IndexOutOfBounds InsufficientApprovals InvalidMemberAddress InvalidMaxProposals InvalidProposal InvalidProposalExpiry InvalidMemberVersion InvalidQuorum MemberIndexOverflow NotAMember NotProposer ProposalAlreadyInVoting ProposalNotExecutable ProposalNotInVoting ReentrantCall TooManyActiveProposals TooManyExecutionAttempts"
const validatorErrors = "InvalidValidator AlreadyValidatorExists NoConfigurationChanging InvalidBlsKeyLength InvalidSignatureLength AlreadyRegisteredBlsKey FailedToVerifyBlsKey InvalidBlsKey InvalidGasTip SameGasTip"
const councilErrors = "AlreadyInBlacklist NotInBlacklist AlreadyInAuthorizedAccountList NotInAuthorizedAccountList"
const setErrors = "ZeroAddressNotAllowed AddressAlreadyExists AddressNotFound IndexOutOfBounds"

type errorProfile struct {
	code common.Hash
	abi  abi.ABI
}

func profile(code, names string) errorProfile {
	entries := []map[string]any{}
	seen := map[string]bool{}
	for _, name := range strings.Fields(names) {
		if seen[name] {
			continue
		}
		seen[name] = true
		entries = append(entries, map[string]any{"type": "error", "name": name, "inputs": []any{}})
	}
	entries = append(entries, map[string]any{"type": "error", "name": "Error", "inputs": []map[string]string{{"name": "message", "type": "string"}}}, map[string]any{"type": "error", "name": "Panic", "inputs": []map[string]string{{"name": "code", "type": "uint256"}}})
	raw, err := json.Marshal(entries)
	if err != nil {
		panic("invalid error contract")
	}
	parsed, err := abi.JSON(bytes.NewReader(raw))
	if err != nil {
		panic("invalid error contract")
	}
	runtime, err := hex.DecodeString(strings.TrimPrefix(code, "0x"))
	if err != nil || len(runtime) == 0 {
		panic("invalid runtime profile")
	}
	return errorProfile{code: crypto.Keccak256Hash(runtime), abi: parsed}
}

var validatorProfile = profile(systemcontracts.GovValidatorContractV1, baseErrors+" "+validatorErrors+" "+setErrors)
var councilProfile = profile(systemcontracts.GovCouncilContractV1, baseErrors+" "+councilErrors+" "+setErrors)

func vmError(err error) (string, string) {
	if err == nil {
		return "succeeded", "none"
	}
	if errors.Is(err, vm.ErrExecutionReverted) {
		return "reverted", "execution_reverted"
	}
	for _, item := range []struct {
		err  error
		code string
	}{{vm.ErrOutOfGas, "out_of_gas"}, {vm.ErrCodeStoreOutOfGas, "code_storage_out_of_gas"}, {vm.ErrDepth, "call_depth"}, {vm.ErrInsufficientBalance, "insufficient_balance"}, {vm.ErrContractAddressCollision, "contract_address_collision"}, {vm.ErrMaxInitCodeSizeExceeded, "init_code_size"}, {vm.ErrMaxCodeSizeExceeded, "code_size"}, {vm.ErrInvalidJump, "invalid_jump"}, {vm.ErrWriteProtection, "write_protection"}, {vm.ErrReturnDataOutOfBounds, "return_data_bounds"}, {vm.ErrGasUintOverflow, "gas_overflow"}, {vm.ErrInvalidCode, "invalid_code"}, {vm.ErrNonceUintOverflow, "nonce_overflow"}, {vm.ErrValueTransferToPrecompile, "precompile_transfer"}, {vm.ErrZeroAddressTransfer, "zero_address_transfer"}} {
		if errors.Is(err, item.err) {
			return "vm_error", item.code
		}
	}
	switch err.(type) {
	case *vm.ErrInvalidOpCode:
		return "vm_error", "invalid_opcode"
	case *vm.ErrStackUnderflow:
		return "vm_error", "stack_underflow"
	case *vm.ErrStackOverflow:
		return "vm_error", "stack_overflow"
	case *vm.ErrBlacklistedAccount:
		return "vm_error", "blacklisted_account"
	}
	return "vm_error", "unclassified"
}
func interpret(f *Frame, sc params.SystemContracts, creation bool, returned []byte) {
	f.Authority = "other"
	f.ABIStatus = "not_reverted"
	f.ErrorName = ""
	var selected *errorProfile
	if !creation {
		to := common.HexToAddress(f.To)
		if sc.GovValidator != nil && to == sc.GovValidator.Address {
			f.Authority = "gov_validator"
			if sc.GovValidator.Version == "v1" {
				selected = &validatorProfile
			}
		}
		if sc.GovCouncil != nil && to == sc.GovCouncil.Address {
			if f.Authority != "other" {
				selected = nil
				f.Authority = "ambiguous"
			} else {
				f.Authority = "gov_council"
				if sc.GovCouncil.Version == "v1" {
					selected = &councilProfile
				}
			}
		}
	}
	if f.Status != "reverted" {
		return
	}
	f.ABIStatus = "unknown_runtime"
	if selected == nil || common.HexToHash(f.AccountCodeHash) != selected.code {
		return
	}
	f.ABIStatus = "empty_revert"
	if len(returned) == 0 {
		return
	}
	f.ABIStatus = "malformed_revert"
	if len(returned) < 4 {
		return
	}
	var id [4]byte
	copy(id[:], returned[:4])
	definition, err := selected.abi.ErrorByID(id)
	if err != nil {
		f.ABIStatus = "unknown_selector"
		return
	}
	values, err := definition.Inputs.Unpack(returned[4:])
	if err != nil {
		return
	}
	canonical, err := definition.Inputs.Pack(values...)
	if err != nil || !bytes.Equal(canonical, returned[4:]) {
		return
	}
	f.ABIStatus = "decoded_revert"
	f.ErrorName = definition.Name
}
