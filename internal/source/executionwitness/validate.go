package executionwitness

import (
	"math/big"
	"reflect"
	"strings"

	"github.com/0xmhha/wbft/crypto/keccak"
)

const validatorCodeHash = "0xb5ce66a9f8c1a08247521c60191f8b11e31e472d8dc26ea163e66de307303dac"
const councilCodeHash = "0x5a6e0f04acf2122487c1c512dc925d5f85a30c4bb6e2a60abba5db009ba472ab"
const baseErrorNames = "AlreadyAMember AlreadyApproved DuplicateMember IndexOutOfBounds InsufficientApprovals InvalidMemberAddress InvalidMaxProposals InvalidProposal InvalidProposalExpiry InvalidMemberVersion InvalidQuorum MemberIndexOverflow NotAMember NotProposer ProposalAlreadyInVoting ProposalNotExecutable ProposalNotInVoting ReentrantCall TooManyActiveProposals TooManyExecutionAttempts ZeroAddressNotAllowed AddressAlreadyExists AddressNotFound"
const validatorErrorNames = "InvalidValidator AlreadyValidatorExists NoConfigurationChanging InvalidBlsKeyLength InvalidSignatureLength AlreadyRegisteredBlsKey FailedToVerifyBlsKey InvalidBlsKey InvalidGasTip SameGasTip"
const councilErrorNames = "AlreadyInBlacklist NotInBlacklist AlreadyInAuthorizedAccountList NotInAuthorizedAccountList"

func member(list, value string) bool {
	for _, s := range strings.Fields(list) {
		if s == value {
			return true
		}
	}
	return false
}
func validDigest(d Digest) bool {
	return d.Bytes >= 0 && d.Bytes <= MaxSourceBytes && hash(d.SHA256, 32) && (d.Bytes != 0 || d == digest(nil))
}
func validFrame(f Frame, index string) bool {
	n, ok := number(index)
	if !ok || n == 0 || f.AuthorityIndex != new(big.Int).SetUint64(n-1).String() || f.Path == nil || len(f.Path) > 128 || !wireHex(f.From, 20) || !wireHex(f.To, 20) || !validDigest(f.Input) || !validDigest(f.Return) || f.Selector != "" && !wireHex(f.Selector, 4) {
		return false
	}
	if !member("CALL CALLCODE DELEGATECALL STATICCALL CREATE CREATE2 SELFDESTRUCT", f.Kind) || !member("other gov_validator gov_council ambiguous", f.Authority) || !member("succeeded reverted vm_error", f.Status) {
		return false
	}
	if f.Status == "succeeded" && f.VMError != "none" || f.Status == "reverted" && f.VMError != "execution_reverted" {
		return false
	}
	if f.Status == "vm_error" && !member("out_of_gas code_storage_out_of_gas call_depth insufficient_balance contract_address_collision init_code_size code_size invalid_jump write_protection return_data_bounds gas_overflow invalid_code nonce_overflow precompile_transfer zero_address_transfer invalid_opcode stack_underflow stack_overflow blacklisted_account unclassified", f.VMError) {
		return false
	}
	if f.Observation == "call_hook" {
		gas, a := number(f.Gas)
		used, b := number(f.GasUsed)
		if !a || !b || used > gas || !wireHex(f.AccountCodeHash, 32) || f.AccountCodeBytes < 0 || f.AccountCodeBytes > MaxSourceBytes {
			return false
		}
	} else if f.Observation != "execution_result" || len(f.Path) != 0 || f.Gas != "" || f.GasUsed != "" || f.AccountCodeHash != "" || f.AccountCodeBytes != 0 || f.ErrorName != "" {
		return false
	}
	if f.Status != "reverted" {
		return f.ABIStatus == "not_reverted" && f.ErrorName == ""
	}
	if !member("unknown_runtime empty_revert malformed_revert unknown_selector decoded_revert", f.ABIStatus) {
		return false
	}
	if f.ABIStatus != "decoded_revert" {
		return f.ErrorName == ""
	}
	if f.Observation != "call_hook" || f.Kind == "CREATE" || f.Kind == "CREATE2" || f.AccountCodeBytes < 1 {
		return false
	}
	names := baseErrorNames + " Error Panic"
	switch f.Authority {
	case "gov_validator":
		if f.AccountCodeHash != validatorCodeHash {
			return false
		}
		names += " " + validatorErrorNames
	case "gov_council":
		if f.AccountCodeHash != councilCodeHash {
			return false
		}
		names += " " + councilErrorNames
	default:
		return false
	}
	if !member(names, f.ErrorName) {
		return false
	}
	if f.ErrorName == "Panic" {
		return f.Return.Bytes == 36
	}
	if f.ErrorName == "Error" {
		return f.Return.Bytes >= 68 && (f.Return.Bytes-4)%32 == 0
	}
	encoded := keccak.Sum256Bytes([]byte(f.ErrorName + "()"))
	return f.Return == digest(encoded[:4])
}
func validate(report Report, s snapshot, origin Origin) error {
	if report.Protocol != Protocol || report.Origin != origin || report.Transactions == nil || len(report.Transactions) != len(s.transactions) || len(report.Transactions) > MaxTransactions {
		return ErrSource
	}
	cid, ok := new(big.Int).SetString(report.Source.ChainID, 10)
	if !ok || cid.Sign() < 0 || cid.BitLen() > 256 || cid.String() != report.Source.ChainID {
		return ErrSource
	}
	expected := s.source
	expected.ChainID = report.Source.ChainID
	if !reflect.DeepEqual(expected, report.Source) {
		return ErrSource
	}
	frames := 0
	logs := 0
	for i, tx := range report.Transactions {
		want := s.transactions[i]
		if tx.Index != want.index || tx.Ordinal != want.ordinal || tx.Hash != want.hash || tx.BlockHash != want.blockHash || !wireHex(tx.From, 20) || tx.To != "" && !wireHex(tx.To, 20) || !validDigest(tx.Input) || !validDigest(tx.Receipt) || tx.Receipt.Bytes < 1 || tx.Selector != "" && !wireHex(tx.Selector, 4) {
			return ErrSource
		}
		if _, ok := number(tx.GasUsed); !ok {
			return ErrSource
		}
		if tx.ReceiptStatus != "succeeded" && tx.ReceiptStatus != "failed" || len(tx.Frames) == 0 || len(tx.Frames) > 4096 {
			return ErrSource
		}
		if tx.Logs == nil || len(tx.Logs) > MaxTransactionLogs || tx.ReceiptStatus == "failed" && len(tx.Logs) != 0 {
			return ErrSource
		}
		logs += len(tx.Logs)
		if logs > MaxLogs {
			return ErrSource
		}
		for _, log := range tx.Logs {
			if !wireHex(log.Address, 20) || log.Topics == nil || len(log.Topics) > 4 || !validDigest(log.Data) {
				return ErrSource
			}
			for _, topic := range log.Topics {
				if !wireHex(topic, 32) {
					return ErrSource
				}
			}
		}
		frames += len(tx.Frames)
		if frames > MaxFrames {
			return ErrSource
		}
		parents := map[string]bool{}
		nextChild := map[string]uint32{}
		lastPath := []uint32{}
		for j, f := range tx.Frames {
			if !validFrame(f, tx.Index) {
				return ErrSource
			}
			if j == 0 {
				if len(f.Path) != 0 || f.From != tx.From || f.Input != tx.Input || f.Selector != tx.Selector || tx.To != "" && f.To != tx.To || tx.To == "" && f.Kind != "CREATE" || tx.To != "" && f.Kind != "CALL" || (f.Status == "succeeded") != (tx.ReceiptStatus == "succeeded") {
					return ErrSource
				}
				rootEffective := f.Status == "succeeded"
				if f.Effective != rootEffective {
					return ErrSource
				}
				if f.Observation == "execution_result" && len(tx.Frames) != 1 {
					return ErrSource
				}
				parents[""] = f.Effective
				continue
			}
			if len(f.Path) == 0 || f.Observation != "call_hook" || len(f.Path)-1 > len(lastPath) {
				return ErrSource
			}
			for k, v := range f.Path[:len(f.Path)-1] {
				if lastPath[k] != v {
					return ErrSource
				}
			}
			lastPath = f.Path
			key := pathKey(f.Path[:len(f.Path)-1])
			parentEffect, found := parents[key]
			if !found || f.Path[len(f.Path)-1] != nextChild[key] {
				return ErrSource
			}
			nextChild[key]++
			if f.Effective != (parentEffect && f.Status == "succeeded") {
				return ErrSource
			}
			child := pathKey(f.Path)
			if _, duplicate := parents[child]; duplicate {
				return ErrSource
			}
			parents[child] = f.Effective
		}
	}
	return nil
}
func pathKey(path []uint32) string {
	var out strings.Builder
	for _, v := range path {
		out.WriteByte('/')
		out.WriteString(new(big.Int).SetUint64(uint64(v)).String())
	}
	return out.String()
}
