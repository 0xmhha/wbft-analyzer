package governance

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type Argument struct {
	Type   string   `json:"type"`
	Value  string   `json:"value,omitempty"`
	Values []string `json:"values,omitempty"`
	Bytes  *Bytes   `json:"bytes,omitempty"`
}
type ContractCall struct {
	Status    string     `json:"status"`
	Signature string     `json:"signature,omitempty"`
	Arguments []Argument `json:"arguments"`
}
type contractMethod struct {
	signature string
	arguments abi.Arguments
}

// These are wire signatures, independently decoded through the standard EVM
// ABI library. Opaque byte arguments are summarized even for known methods.
var contractMethods = func() map[string]contractMethod {
	out := map[string]contractMethod{}
	for _, signature := range []string{
		"approveProposal(uint256)", "disapproveProposal(uint256)",
		"executeProposal(uint256)", "executeWithFailure(uint256)",
		"cancelProposal(uint256)", "expireProposal(uint256)",
		"proposeAddMember(address,uint32)", "proposeRemoveMember(address,uint32)",
		"proposeChangeQuorum(uint32)", "proposeChangeMaxProposals(uint256)",
		"changeMember(address)", "configureValidator(address,bytes,bytes)",
		"proposeGasTip(uint256)", "proposeAddBlacklist(address)",
		"proposeRemoveBlacklist(address)", "proposeAddBlacklistBatch(address[])",
		"proposeRemoveBlacklistBatch(address[])", "proposeAddAuthorizedAccount(address)",
		"proposeRemoveAuthorizedAccount(address)", "proposeAddAuthorizedAccountBatch(address[])",
		"proposeRemoveAuthorizedAccountBatch(address[])",
	} {
		args := abi.Arguments{}
		start := strings.IndexByte(signature, '(')
		for _, name := range strings.Split(signature[start+1:len(signature)-1], ",") {
			typ, err := abi.NewType(name, "", nil)
			if err != nil {
				panic("invalid static governance ABI")
			}
			args = append(args, abi.Argument{Type: typ})
		}
		selector := hex.EncodeToString(crypto.Keccak256([]byte(signature))[:4])
		if _, exists := out[selector]; exists {
			panic("duplicate static governance selector")
		}
		out[selector] = contractMethod{signature: signature, arguments: args}
	}
	return out
}()

func contractCall(input []byte) ContractCall {
	out := ContractCall{Status: "unknown", Arguments: []Argument{}}
	if len(input) < 4 {
		return out
	}
	method, ok := contractMethods[hex.EncodeToString(input[:4])]
	if !ok {
		return out
	}
	out.Signature = method.signature
	out.Status = "malformed"
	values, err := method.arguments.Unpack(input[4:])
	if err != nil {
		return out
	}
	encoded, err := method.arguments.Pack(values...)
	if err != nil || !bytes.Equal(encoded, input[4:]) {
		return out
	}
	args := make([]Argument, 0, len(values))
	for i, value := range values {
		arg := Argument{Type: method.arguments[i].Type.String()}
		switch v := value.(type) {
		case *big.Int:
			arg.Value = "0x" + v.Text(16)
		case uint32:
			arg.Value = "0x" + new(big.Int).SetUint64(uint64(v)).Text(16)
		case common.Address:
			arg.Value = strings.ToLower(v.Hex())
		case []common.Address:
			if len(v) > 4096 {
				return out
			}
			arg.Values = make([]string, 0, len(v))
			for _, addr := range v {
				arg.Values = append(arg.Values, strings.ToLower(addr.Hex()))
			}
		case []byte:
			b := summary(v)
			arg.Bytes = &b
		default:
			return out
		}
		args = append(args, arg)
	}
	out.Status, out.Arguments = "decoded", args
	return out
}

func outcome(value string) (string, string) {
	if value == "success" || value == "revert" {
		return value, ""
	}
	// Only contract-defined error names may become labels. Unknown strings
	// remain unavailable labels while their digest is retained separately.
	switch value {
	case "AlreadyAMember", "AlreadyApproved", "IndexOutOfBounds", "InsufficientApprovals",
		"InvalidMemberAddress", "InvalidMaxProposals", "InvalidProposal", "InvalidProposalExpiry",
		"InvalidMemberVersion", "InvalidQuorum", "MemberIndexOverflow", "NotAMember", "NotProposer",
		"ProposalAlreadyInVoting", "ProposalNotExecutable", "ProposalNotInVoting", "ReentrantCall",
		"TooManyActiveProposals", "InvalidValidator", "AlreadyValidatorExists", "NoConfigurationChanging",
		"InvalidBlsKeyLength", "InvalidSignatureLength", "AlreadyRegisteredBlsKey", "FailedToVerifyBlsKey",
		"InvalidBlsKey", "SameGasTip", "AlreadyInBlacklist", "NotInBlacklist",
		"AlreadyInAuthorizedAccountList", "NotInAuthorizedAccountList", "ZeroAddressNotAllowed",
		"AddressAlreadyExists", "AddressNotFound", "Panic", "Error":
		return "revert", value
	default:
		return "unknown", ""
	}
}
