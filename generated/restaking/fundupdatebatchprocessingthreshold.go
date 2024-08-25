// Code generated by https://github.com/gagliardetto/anchor-go. DO NOT EDIT.

package restaking

import (
	"errors"
	ag_binary "github.com/gagliardetto/binary"
	ag_solanago "github.com/gagliardetto/solana-go"
	ag_format "github.com/gagliardetto/solana-go/text/format"
	ag_treeout "github.com/gagliardetto/treeout"
)

// FundUpdateBatchProcessingThreshold is the `fund_update_batch_processing_threshold` instruction.
type FundUpdateBatchProcessingThreshold struct {
	Amount   *uint64 `bin:"optional"`
	Duration *int64  `bin:"optional"`

	// [0] = [WRITE, SIGNER] admin
	//
	// [1] = [WRITE] fund
	//
	// [2] = [] receipt_token_mint
	ag_solanago.AccountMetaSlice `bin:"-"`
}

// NewFundUpdateBatchProcessingThresholdInstructionBuilder creates a new `FundUpdateBatchProcessingThreshold` instruction builder.
func NewFundUpdateBatchProcessingThresholdInstructionBuilder() *FundUpdateBatchProcessingThreshold {
	nd := &FundUpdateBatchProcessingThreshold{
		AccountMetaSlice: make(ag_solanago.AccountMetaSlice, 3),
	}
	nd.AccountMetaSlice[0] = ag_solanago.Meta(ag_solanago.MustPublicKeyFromBase58("91zBeWL8kHBaMtaVrHwWsck1UacDKvje82QQ3HE2k8mJ")).WRITE().SIGNER()
	nd.AccountMetaSlice[2] = ag_solanago.Meta(ag_solanago.MustPublicKeyFromBase58("FRAGsJAbW4cHk2DYhtAWohV6MUMauJHCFtT1vGvRwnXN"))
	return nd
}

// SetAmount sets the "amount" parameter.
func (inst *FundUpdateBatchProcessingThreshold) SetAmount(amount uint64) *FundUpdateBatchProcessingThreshold {
	inst.Amount = &amount
	return inst
}

// SetDuration sets the "duration" parameter.
func (inst *FundUpdateBatchProcessingThreshold) SetDuration(duration int64) *FundUpdateBatchProcessingThreshold {
	inst.Duration = &duration
	return inst
}

// SetAdminAccount sets the "admin" account.
func (inst *FundUpdateBatchProcessingThreshold) SetAdminAccount(admin ag_solanago.PublicKey) *FundUpdateBatchProcessingThreshold {
	inst.AccountMetaSlice[0] = ag_solanago.Meta(admin).WRITE().SIGNER()
	return inst
}

// GetAdminAccount gets the "admin" account.
func (inst *FundUpdateBatchProcessingThreshold) GetAdminAccount() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(0)
}

// SetFundAccount sets the "fund" account.
func (inst *FundUpdateBatchProcessingThreshold) SetFundAccount(fund ag_solanago.PublicKey) *FundUpdateBatchProcessingThreshold {
	inst.AccountMetaSlice[1] = ag_solanago.Meta(fund).WRITE()
	return inst
}

func (inst *FundUpdateBatchProcessingThreshold) findFindFundAddress(receiptTokenMint ag_solanago.PublicKey, knownBumpSeed uint8) (pda ag_solanago.PublicKey, bumpSeed uint8, err error) {
	var seeds [][]byte
	// const: fund_seed
	seeds = append(seeds, []byte{byte(0x66), byte(0x75), byte(0x6e), byte(0x64), byte(0x5f), byte(0x73), byte(0x65), byte(0x65), byte(0x64)})
	// path: receiptTokenMint
	seeds = append(seeds, receiptTokenMint.Bytes())

	if knownBumpSeed != 0 {
		seeds = append(seeds, []byte{byte(bumpSeed)})
		pda, err = ag_solanago.CreateProgramAddress(seeds, ProgramID)
	} else {
		pda, bumpSeed, err = ag_solanago.FindProgramAddress(seeds, ProgramID)
	}
	return
}

// FindFundAddressWithBumpSeed calculates Fund account address with given seeds and a known bump seed.
func (inst *FundUpdateBatchProcessingThreshold) FindFundAddressWithBumpSeed(receiptTokenMint ag_solanago.PublicKey, bumpSeed uint8) (pda ag_solanago.PublicKey, err error) {
	pda, _, err = inst.findFindFundAddress(receiptTokenMint, bumpSeed)
	return
}

func (inst *FundUpdateBatchProcessingThreshold) MustFindFundAddressWithBumpSeed(receiptTokenMint ag_solanago.PublicKey, bumpSeed uint8) (pda ag_solanago.PublicKey) {
	pda, _, err := inst.findFindFundAddress(receiptTokenMint, bumpSeed)
	if err != nil {
		panic(err)
	}
	return
}

// FindFundAddress finds Fund account address with given seeds.
func (inst *FundUpdateBatchProcessingThreshold) FindFundAddress(receiptTokenMint ag_solanago.PublicKey) (pda ag_solanago.PublicKey, bumpSeed uint8, err error) {
	pda, bumpSeed, err = inst.findFindFundAddress(receiptTokenMint, 0)
	return
}

func (inst *FundUpdateBatchProcessingThreshold) MustFindFundAddress(receiptTokenMint ag_solanago.PublicKey) (pda ag_solanago.PublicKey) {
	pda, _, err := inst.findFindFundAddress(receiptTokenMint, 0)
	if err != nil {
		panic(err)
	}
	return
}

// GetFundAccount gets the "fund" account.
func (inst *FundUpdateBatchProcessingThreshold) GetFundAccount() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(1)
}

// SetReceiptTokenMintAccount sets the "receipt_token_mint" account.
func (inst *FundUpdateBatchProcessingThreshold) SetReceiptTokenMintAccount(receiptTokenMint ag_solanago.PublicKey) *FundUpdateBatchProcessingThreshold {
	inst.AccountMetaSlice[2] = ag_solanago.Meta(receiptTokenMint)
	return inst
}

// GetReceiptTokenMintAccount gets the "receipt_token_mint" account.
func (inst *FundUpdateBatchProcessingThreshold) GetReceiptTokenMintAccount() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(2)
}

func (inst FundUpdateBatchProcessingThreshold) Build() *Instruction {
	return &Instruction{BaseVariant: ag_binary.BaseVariant{
		Impl:   inst,
		TypeID: Instruction_FundUpdateBatchProcessingThreshold,
	}}
}

// ValidateAndBuild validates the instruction parameters and accounts;
// if there is a validation error, it returns the error.
// Otherwise, it builds and returns the instruction.
func (inst FundUpdateBatchProcessingThreshold) ValidateAndBuild() (*Instruction, error) {
	if err := inst.Validate(); err != nil {
		return nil, err
	}
	return inst.Build(), nil
}

func (inst *FundUpdateBatchProcessingThreshold) Validate() error {
	// Check whether all (required) parameters are set:
	{
	}

	// Check whether all (required) accounts are set:
	{
		if inst.AccountMetaSlice[0] == nil {
			return errors.New("accounts.Admin is not set")
		}
		if inst.AccountMetaSlice[1] == nil {
			return errors.New("accounts.Fund is not set")
		}
		if inst.AccountMetaSlice[2] == nil {
			return errors.New("accounts.ReceiptTokenMint is not set")
		}
	}
	return nil
}

func (inst *FundUpdateBatchProcessingThreshold) EncodeToTree(parent ag_treeout.Branches) {
	parent.Child(ag_format.Program(ProgramName, ProgramID)).
		//
		ParentFunc(func(programBranch ag_treeout.Branches) {
			programBranch.Child(ag_format.Instruction("FundUpdateBatchProcessingThreshold")).
				//
				ParentFunc(func(instructionBranch ag_treeout.Branches) {

					// Parameters of the instruction:
					instructionBranch.Child("Params[len=2]").ParentFunc(func(paramsBranch ag_treeout.Branches) {
						paramsBranch.Child(ag_format.Param("  Amount (OPT)", inst.Amount))
						paramsBranch.Child(ag_format.Param("Duration (OPT)", inst.Duration))
					})

					// Accounts of the instruction:
					instructionBranch.Child("Accounts[len=3]").ParentFunc(func(accountsBranch ag_treeout.Branches) {
						accountsBranch.Child(ag_format.Meta("             admin", inst.AccountMetaSlice.Get(0)))
						accountsBranch.Child(ag_format.Meta("              fund", inst.AccountMetaSlice.Get(1)))
						accountsBranch.Child(ag_format.Meta("receipt_token_mint", inst.AccountMetaSlice.Get(2)))
					})
				})
		})
}

func (obj FundUpdateBatchProcessingThreshold) MarshalWithEncoder(encoder *ag_binary.Encoder) (err error) {
	// Serialize `Amount` param (optional):
	{
		if obj.Amount == nil {
			err = encoder.WriteBool(false)
			if err != nil {
				return err
			}
		} else {
			err = encoder.WriteBool(true)
			if err != nil {
				return err
			}
			err = encoder.Encode(obj.Amount)
			if err != nil {
				return err
			}
		}
	}
	// Serialize `Duration` param (optional):
	{
		if obj.Duration == nil {
			err = encoder.WriteBool(false)
			if err != nil {
				return err
			}
		} else {
			err = encoder.WriteBool(true)
			if err != nil {
				return err
			}
			err = encoder.Encode(obj.Duration)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
func (obj *FundUpdateBatchProcessingThreshold) UnmarshalWithDecoder(decoder *ag_binary.Decoder) (err error) {
	// Deserialize `Amount` (optional):
	{
		ok, err := decoder.ReadBool()
		if err != nil {
			return err
		}
		if ok {
			err = decoder.Decode(&obj.Amount)
			if err != nil {
				return err
			}
		}
	}
	// Deserialize `Duration` (optional):
	{
		ok, err := decoder.ReadBool()
		if err != nil {
			return err
		}
		if ok {
			err = decoder.Decode(&obj.Duration)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// NewFundUpdateBatchProcessingThresholdInstruction declares a new FundUpdateBatchProcessingThreshold instruction with the provided parameters and accounts.
func NewFundUpdateBatchProcessingThresholdInstruction(
	// Parameters:
	amount uint64,
	duration int64,
	// Accounts:
	admin ag_solanago.PublicKey,
	fund ag_solanago.PublicKey,
	receiptTokenMint ag_solanago.PublicKey) *FundUpdateBatchProcessingThreshold {
	return NewFundUpdateBatchProcessingThresholdInstructionBuilder().
		SetAmount(amount).
		SetDuration(duration).
		SetAdminAccount(admin).
		SetFundAccount(fund).
		SetReceiptTokenMintAccount(receiptTokenMint)
}
