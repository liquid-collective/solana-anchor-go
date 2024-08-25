// Code generated by https://github.com/gagliardetto/anchor-go. DO NOT EDIT.

package restaking

import (
	"errors"
	ag_binary "github.com/gagliardetto/binary"
	ag_solanago "github.com/gagliardetto/solana-go"
	ag_format "github.com/gagliardetto/solana-go/text/format"
	ag_treeout "github.com/gagliardetto/treeout"
)

// FundUpdateWithdrawalEnabledFlag is the `fund_update_withdrawal_enabled_flag` instruction.
type FundUpdateWithdrawalEnabledFlag struct {
	Flag *bool

	// [0] = [WRITE, SIGNER] admin
	//
	// [1] = [WRITE] fund
	//
	// [2] = [] receipt_token_mint
	ag_solanago.AccountMetaSlice `bin:"-"`
}

// NewFundUpdateWithdrawalEnabledFlagInstructionBuilder creates a new `FundUpdateWithdrawalEnabledFlag` instruction builder.
func NewFundUpdateWithdrawalEnabledFlagInstructionBuilder() *FundUpdateWithdrawalEnabledFlag {
	nd := &FundUpdateWithdrawalEnabledFlag{
		AccountMetaSlice: make(ag_solanago.AccountMetaSlice, 3),
	}
	nd.AccountMetaSlice[0] = ag_solanago.Meta(ag_solanago.MustPublicKeyFromBase58("91zBeWL8kHBaMtaVrHwWsck1UacDKvje82QQ3HE2k8mJ")).WRITE().SIGNER()
	nd.AccountMetaSlice[2] = ag_solanago.Meta(ag_solanago.MustPublicKeyFromBase58("FRAGsJAbW4cHk2DYhtAWohV6MUMauJHCFtT1vGvRwnXN"))
	return nd
}

// SetFlag sets the "flag" parameter.
func (inst *FundUpdateWithdrawalEnabledFlag) SetFlag(flag bool) *FundUpdateWithdrawalEnabledFlag {
	inst.Flag = &flag
	return inst
}

// SetAdminAccount sets the "admin" account.
func (inst *FundUpdateWithdrawalEnabledFlag) SetAdminAccount(admin ag_solanago.PublicKey) *FundUpdateWithdrawalEnabledFlag {
	inst.AccountMetaSlice[0] = ag_solanago.Meta(admin).WRITE().SIGNER()
	return inst
}

// GetAdminAccount gets the "admin" account.
func (inst *FundUpdateWithdrawalEnabledFlag) GetAdminAccount() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(0)
}

// SetFundAccount sets the "fund" account.
func (inst *FundUpdateWithdrawalEnabledFlag) SetFundAccount(fund ag_solanago.PublicKey) *FundUpdateWithdrawalEnabledFlag {
	inst.AccountMetaSlice[1] = ag_solanago.Meta(fund).WRITE()
	return inst
}

func (inst *FundUpdateWithdrawalEnabledFlag) findFindFundAddress(receiptTokenMint ag_solanago.PublicKey, knownBumpSeed uint8) (pda ag_solanago.PublicKey, bumpSeed uint8, err error) {
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
func (inst *FundUpdateWithdrawalEnabledFlag) FindFundAddressWithBumpSeed(receiptTokenMint ag_solanago.PublicKey, bumpSeed uint8) (pda ag_solanago.PublicKey, err error) {
	pda, _, err = inst.findFindFundAddress(receiptTokenMint, bumpSeed)
	return
}

func (inst *FundUpdateWithdrawalEnabledFlag) MustFindFundAddressWithBumpSeed(receiptTokenMint ag_solanago.PublicKey, bumpSeed uint8) (pda ag_solanago.PublicKey) {
	pda, _, err := inst.findFindFundAddress(receiptTokenMint, bumpSeed)
	if err != nil {
		panic(err)
	}
	return
}

// FindFundAddress finds Fund account address with given seeds.
func (inst *FundUpdateWithdrawalEnabledFlag) FindFundAddress(receiptTokenMint ag_solanago.PublicKey) (pda ag_solanago.PublicKey, bumpSeed uint8, err error) {
	pda, bumpSeed, err = inst.findFindFundAddress(receiptTokenMint, 0)
	return
}

func (inst *FundUpdateWithdrawalEnabledFlag) MustFindFundAddress(receiptTokenMint ag_solanago.PublicKey) (pda ag_solanago.PublicKey) {
	pda, _, err := inst.findFindFundAddress(receiptTokenMint, 0)
	if err != nil {
		panic(err)
	}
	return
}

// GetFundAccount gets the "fund" account.
func (inst *FundUpdateWithdrawalEnabledFlag) GetFundAccount() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(1)
}

// SetReceiptTokenMintAccount sets the "receipt_token_mint" account.
func (inst *FundUpdateWithdrawalEnabledFlag) SetReceiptTokenMintAccount(receiptTokenMint ag_solanago.PublicKey) *FundUpdateWithdrawalEnabledFlag {
	inst.AccountMetaSlice[2] = ag_solanago.Meta(receiptTokenMint)
	return inst
}

// GetReceiptTokenMintAccount gets the "receipt_token_mint" account.
func (inst *FundUpdateWithdrawalEnabledFlag) GetReceiptTokenMintAccount() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(2)
}

func (inst FundUpdateWithdrawalEnabledFlag) Build() *Instruction {
	return &Instruction{BaseVariant: ag_binary.BaseVariant{
		Impl:   inst,
		TypeID: Instruction_FundUpdateWithdrawalEnabledFlag,
	}}
}

// ValidateAndBuild validates the instruction parameters and accounts;
// if there is a validation error, it returns the error.
// Otherwise, it builds and returns the instruction.
func (inst FundUpdateWithdrawalEnabledFlag) ValidateAndBuild() (*Instruction, error) {
	if err := inst.Validate(); err != nil {
		return nil, err
	}
	return inst.Build(), nil
}

func (inst *FundUpdateWithdrawalEnabledFlag) Validate() error {
	// Check whether all (required) parameters are set:
	{
		if inst.Flag == nil {
			return errors.New("Flag parameter is not set")
		}
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

func (inst *FundUpdateWithdrawalEnabledFlag) EncodeToTree(parent ag_treeout.Branches) {
	parent.Child(ag_format.Program(ProgramName, ProgramID)).
		//
		ParentFunc(func(programBranch ag_treeout.Branches) {
			programBranch.Child(ag_format.Instruction("FundUpdateWithdrawalEnabledFlag")).
				//
				ParentFunc(func(instructionBranch ag_treeout.Branches) {

					// Parameters of the instruction:
					instructionBranch.Child("Params[len=1]").ParentFunc(func(paramsBranch ag_treeout.Branches) {
						paramsBranch.Child(ag_format.Param("Flag", *inst.Flag))
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

func (obj FundUpdateWithdrawalEnabledFlag) MarshalWithEncoder(encoder *ag_binary.Encoder) (err error) {
	// Serialize `Flag` param:
	err = encoder.Encode(obj.Flag)
	if err != nil {
		return err
	}
	return nil
}
func (obj *FundUpdateWithdrawalEnabledFlag) UnmarshalWithDecoder(decoder *ag_binary.Decoder) (err error) {
	// Deserialize `Flag`:
	err = decoder.Decode(&obj.Flag)
	if err != nil {
		return err
	}
	return nil
}

// NewFundUpdateWithdrawalEnabledFlagInstruction declares a new FundUpdateWithdrawalEnabledFlag instruction with the provided parameters and accounts.
func NewFundUpdateWithdrawalEnabledFlagInstruction(
	// Parameters:
	flag bool,
	// Accounts:
	admin ag_solanago.PublicKey,
	fund ag_solanago.PublicKey,
	receiptTokenMint ag_solanago.PublicKey) *FundUpdateWithdrawalEnabledFlag {
	return NewFundUpdateWithdrawalEnabledFlagInstructionBuilder().
		SetFlag(flag).
		SetAdminAccount(admin).
		SetFundAccount(fund).
		SetReceiptTokenMintAccount(receiptTokenMint)
}
