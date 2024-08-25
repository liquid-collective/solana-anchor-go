// Code generated by https://github.com/gagliardetto/anchor-go. DO NOT EDIT.

package restaking

import (
	"bytes"
	"fmt"
	ag_spew "github.com/davecgh/go-spew/spew"
	ag_binary "github.com/gagliardetto/binary"
	ag_solanago "github.com/gagliardetto/solana-go"
	ag_text "github.com/gagliardetto/solana-go/text"
	ag_treeout "github.com/gagliardetto/treeout"
)

var ProgramID ag_solanago.PublicKey

func SetProgramID(PublicKey ag_solanago.PublicKey) {
	ProgramID = PublicKey
	ag_solanago.RegisterInstructionDecoder(ProgramID, registryDecodeInstruction)
}

const ProgramName = "Restaking"

func init() {
	if !ProgramID.IsZero() {
		ag_solanago.RegisterInstructionDecoder(ProgramID, registryDecodeInstruction)
	}
}

var (
	Instruction_FundAddSupportedToken = ag_binary.TypeID([8]byte{144, 50, 243, 20, 77, 240, 96, 158})

	Instruction_FundCancelWithdrawalRequest = ag_binary.TypeID([8]byte{57, 27, 165, 22, 12, 154, 122, 39})

	Instruction_FundDepositSol = ag_binary.TypeID([8]byte{49, 154, 147, 201, 152, 214, 141, 42})

	Instruction_FundDepositToken = ag_binary.TypeID([8]byte{0, 214, 129, 126, 94, 183, 147, 138})

	Instruction_FundInitialize = ag_binary.TypeID([8]byte{180, 5, 190, 65, 131, 242, 240, 233})

	Instruction_FundInitializeBatchProcessingThreshold = ag_binary.TypeID([8]byte{189, 86, 144, 160, 80, 32, 52, 172})

	Instruction_FundInitializeSolWithdrawalFeeRate = ag_binary.TypeID([8]byte{169, 203, 196, 46, 31, 239, 53, 127})

	Instruction_FundInitializeWithdrawalEnabledFlag = ag_binary.TypeID([8]byte{201, 191, 67, 3, 86, 51, 236, 86})

	Instruction_FundRequestWithdrawal = ag_binary.TypeID([8]byte{7, 152, 197, 136, 120, 91, 3, 60})

	Instruction_FundResetReceiptTokenPrice = ag_binary.TypeID([8]byte{26, 251, 29, 3, 194, 222, 221, 92})

	Instruction_FundUpdateBatchProcessingThreshold = ag_binary.TypeID([8]byte{139, 58, 227, 245, 152, 176, 120, 184})

	Instruction_FundUpdatePrice = ag_binary.TypeID([8]byte{231, 124, 147, 194, 249, 64, 228, 186})

	Instruction_FundUpdateSolWithdrawalFeeRate = ag_binary.TypeID([8]byte{141, 108, 26, 242, 215, 223, 138, 189})

	Instruction_FundUpdateSupportedToken = ag_binary.TypeID([8]byte{31, 227, 127, 6, 162, 136, 15, 140})

	Instruction_FundUpdateWithdrawalEnabledFlag = ag_binary.TypeID([8]byte{72, 27, 0, 37, 46, 214, 205, 21})

	Instruction_FundWithdraw = ag_binary.TypeID([8]byte{15, 43, 36, 110, 91, 130, 216, 217})

	Instruction_LogMessage = ag_binary.TypeID([8]byte{148, 4, 44, 34, 202, 5, 83, 115})

	Instruction_OperatorRun = ag_binary.TypeID([8]byte{135, 14, 129, 128, 142, 77, 31, 12})

	Instruction_OperatorRunIfNeeded = ag_binary.TypeID([8]byte{104, 151, 73, 34, 54, 4, 79, 210})

	Instruction_TokenInitializeExtraAccountMetaList = ag_binary.TypeID([8]byte{43, 34, 13, 49, 167, 88, 235, 235})

	Instruction_TokenTransferHook = ag_binary.TypeID([8]byte{105, 37, 101, 197, 75, 251, 102, 26})
)

// InstructionIDToName returns the name of the instruction given its ID.
func InstructionIDToName(id ag_binary.TypeID) string {
	switch id {
	case Instruction_FundAddSupportedToken:
		return "FundAddSupportedToken"
	case Instruction_FundCancelWithdrawalRequest:
		return "FundCancelWithdrawalRequest"
	case Instruction_FundDepositSol:
		return "FundDepositSol"
	case Instruction_FundDepositToken:
		return "FundDepositToken"
	case Instruction_FundInitialize:
		return "FundInitialize"
	case Instruction_FundInitializeBatchProcessingThreshold:
		return "FundInitializeBatchProcessingThreshold"
	case Instruction_FundInitializeSolWithdrawalFeeRate:
		return "FundInitializeSolWithdrawalFeeRate"
	case Instruction_FundInitializeWithdrawalEnabledFlag:
		return "FundInitializeWithdrawalEnabledFlag"
	case Instruction_FundRequestWithdrawal:
		return "FundRequestWithdrawal"
	case Instruction_FundResetReceiptTokenPrice:
		return "FundResetReceiptTokenPrice"
	case Instruction_FundUpdateBatchProcessingThreshold:
		return "FundUpdateBatchProcessingThreshold"
	case Instruction_FundUpdatePrice:
		return "FundUpdatePrice"
	case Instruction_FundUpdateSolWithdrawalFeeRate:
		return "FundUpdateSolWithdrawalFeeRate"
	case Instruction_FundUpdateSupportedToken:
		return "FundUpdateSupportedToken"
	case Instruction_FundUpdateWithdrawalEnabledFlag:
		return "FundUpdateWithdrawalEnabledFlag"
	case Instruction_FundWithdraw:
		return "FundWithdraw"
	case Instruction_LogMessage:
		return "LogMessage"
	case Instruction_OperatorRun:
		return "OperatorRun"
	case Instruction_OperatorRunIfNeeded:
		return "OperatorRunIfNeeded"
	case Instruction_TokenInitializeExtraAccountMetaList:
		return "TokenInitializeExtraAccountMetaList"
	case Instruction_TokenTransferHook:
		return "TokenTransferHook"
	default:
		return ""
	}
}

type Instruction struct {
	ag_binary.BaseVariant
}

func (inst *Instruction) EncodeToTree(parent ag_treeout.Branches) {
	if enToTree, ok := inst.Impl.(ag_text.EncodableToTree); ok {
		enToTree.EncodeToTree(parent)
	} else {
		parent.Child(ag_spew.Sdump(inst))
	}
}

var InstructionImplDef = ag_binary.NewVariantDefinition(
	ag_binary.AnchorTypeIDEncoding,
	[]ag_binary.VariantType{
		{
			Name: "fund_add_supported_token", Type: (*FundAddSupportedToken)(nil),
		},
		{
			Name: "fund_cancel_withdrawal_request", Type: (*FundCancelWithdrawalRequest)(nil),
		},
		{
			Name: "fund_deposit_sol", Type: (*FundDepositSol)(nil),
		},
		{
			Name: "fund_deposit_token", Type: (*FundDepositToken)(nil),
		},
		{
			Name: "fund_initialize", Type: (*FundInitialize)(nil),
		},
		{
			Name: "fund_initialize_batch_processing_threshold", Type: (*FundInitializeBatchProcessingThreshold)(nil),
		},
		{
			Name: "fund_initialize_sol_withdrawal_fee_rate", Type: (*FundInitializeSolWithdrawalFeeRate)(nil),
		},
		{
			Name: "fund_initialize_withdrawal_enabled_flag", Type: (*FundInitializeWithdrawalEnabledFlag)(nil),
		},
		{
			Name: "fund_request_withdrawal", Type: (*FundRequestWithdrawal)(nil),
		},
		{
			Name: "fund_reset_receipt_token_price", Type: (*FundResetReceiptTokenPrice)(nil),
		},
		{
			Name: "fund_update_batch_processing_threshold", Type: (*FundUpdateBatchProcessingThreshold)(nil),
		},
		{
			Name: "fund_update_price", Type: (*FundUpdatePrice)(nil),
		},
		{
			Name: "fund_update_sol_withdrawal_fee_rate", Type: (*FundUpdateSolWithdrawalFeeRate)(nil),
		},
		{
			Name: "fund_update_supported_token", Type: (*FundUpdateSupportedToken)(nil),
		},
		{
			Name: "fund_update_withdrawal_enabled_flag", Type: (*FundUpdateWithdrawalEnabledFlag)(nil),
		},
		{
			Name: "fund_withdraw", Type: (*FundWithdraw)(nil),
		},
		{
			Name: "log_message", Type: (*LogMessage)(nil),
		},
		{
			Name: "operator_run", Type: (*OperatorRun)(nil),
		},
		{
			Name: "operator_run_if_needed", Type: (*OperatorRunIfNeeded)(nil),
		},
		{
			Name: "token_initialize_extra_account_meta_list", Type: (*TokenInitializeExtraAccountMetaList)(nil),
		},
		{
			Name: "token_transfer_hook", Type: (*TokenTransferHook)(nil),
		},
	},
)

func (inst *Instruction) ProgramID() ag_solanago.PublicKey {
	return ProgramID
}

func (inst *Instruction) Accounts() (out []*ag_solanago.AccountMeta) {
	return inst.Impl.(ag_solanago.AccountsGettable).GetAccounts()
}

func (inst *Instruction) Data() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := ag_binary.NewBorshEncoder(buf).Encode(inst); err != nil {
		return nil, fmt.Errorf("unable to encode instruction: %w", err)
	}
	return buf.Bytes(), nil
}

func (inst *Instruction) TextEncode(encoder *ag_text.Encoder, option *ag_text.Option) error {
	return encoder.Encode(inst.Impl, option)
}

func (inst *Instruction) UnmarshalWithDecoder(decoder *ag_binary.Decoder) error {
	return inst.BaseVariant.UnmarshalBinaryVariant(decoder, InstructionImplDef)
}

func (inst *Instruction) MarshalWithEncoder(encoder *ag_binary.Encoder) error {
	err := encoder.WriteBytes(inst.TypeID.Bytes(), false)
	if err != nil {
		return fmt.Errorf("unable to write variant type: %w", err)
	}
	return encoder.Encode(inst.Impl)
}

func registryDecodeInstruction(accounts []*ag_solanago.AccountMeta, data []byte) (interface{}, error) {
	inst, err := decodeInstruction(accounts, data)
	if err != nil {
		return nil, err
	}
	return inst, nil
}

func decodeInstruction(accounts []*ag_solanago.AccountMeta, data []byte) (*Instruction, error) {
	inst := new(Instruction)
	if err := ag_binary.NewBorshDecoder(data).Decode(inst); err != nil {
		return nil, fmt.Errorf("unable to decode instruction: %w", err)
	}
	if v, ok := inst.Impl.(ag_solanago.AccountsSettable); ok {
		err := v.SetAccounts(accounts)
		if err != nil {
			return nil, fmt.Errorf("unable to set accounts for instruction: %w", err)
		}
	}
	return inst, nil
}

func DecodeInstructions(message *ag_solanago.Message) (instructions []*Instruction, err error) {
	for _, ins := range message.Instructions {
		var programID ag_solanago.PublicKey
		if programID, err = message.Program(ins.ProgramIDIndex); err != nil {
			return
		}
		if !programID.Equals(ProgramID) {
			continue
		}
		var accounts []*ag_solanago.AccountMeta
		if accounts, err = ins.ResolveInstructionAccounts(message); err != nil {
			return
		}
		var insDecoded *Instruction
		if insDecoded, err = decodeInstruction(accounts, ins.Data); err != nil {
			return
		}
		instructions = append(instructions, insDecoded)
	}
	return
}
