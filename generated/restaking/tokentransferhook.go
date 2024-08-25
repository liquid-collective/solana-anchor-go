// Code generated by https://github.com/gagliardetto/anchor-go. DO NOT EDIT.

package restaking

import (
	"errors"
	ag_binary "github.com/gagliardetto/binary"
	ag_solanago "github.com/gagliardetto/solana-go"
	ag_format "github.com/gagliardetto/solana-go/text/format"
	ag_treeout "github.com/gagliardetto/treeout"
)

// TokenTransferHook is the `token_transfer_hook` instruction.
type TokenTransferHook struct {
	Amount *uint64

	// [0] = [] source_token_account
	//
	// [1] = [] receipt_token_mint
	//
	// [2] = [] destination_token_account
	//
	// [3] = [] owner
	//
	// [4] = [] extra_account_meta_list
	//
	// [5] = [WRITE] fund
	ag_solanago.AccountMetaSlice `bin:"-"`
}

// NewTokenTransferHookInstructionBuilder creates a new `TokenTransferHook` instruction builder.
func NewTokenTransferHookInstructionBuilder() *TokenTransferHook {
	nd := &TokenTransferHook{
		AccountMetaSlice: make(ag_solanago.AccountMetaSlice, 6),
	}
	nd.AccountMetaSlice[1] = ag_solanago.Meta(ag_solanago.MustPublicKeyFromBase58("FRAGsJAbW4cHk2DYhtAWohV6MUMauJHCFtT1vGvRwnXN"))
	return nd
}

// SetAmount sets the "amount" parameter.
func (inst *TokenTransferHook) SetAmount(amount uint64) *TokenTransferHook {
	inst.Amount = &amount
	return inst
}

// SetSourceTokenAccountAccount sets the "source_token_account" account.
func (inst *TokenTransferHook) SetSourceTokenAccountAccount(sourceTokenAccount ag_solanago.PublicKey) *TokenTransferHook {
	inst.AccountMetaSlice[0] = ag_solanago.Meta(sourceTokenAccount)
	return inst
}

// GetSourceTokenAccountAccount gets the "source_token_account" account.
func (inst *TokenTransferHook) GetSourceTokenAccountAccount() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(0)
}

// SetReceiptTokenMintAccount sets the "receipt_token_mint" account.
func (inst *TokenTransferHook) SetReceiptTokenMintAccount(receiptTokenMint ag_solanago.PublicKey) *TokenTransferHook {
	inst.AccountMetaSlice[1] = ag_solanago.Meta(receiptTokenMint)
	return inst
}

// GetReceiptTokenMintAccount gets the "receipt_token_mint" account.
func (inst *TokenTransferHook) GetReceiptTokenMintAccount() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(1)
}

// SetDestinationTokenAccountAccount sets the "destination_token_account" account.
func (inst *TokenTransferHook) SetDestinationTokenAccountAccount(destinationTokenAccount ag_solanago.PublicKey) *TokenTransferHook {
	inst.AccountMetaSlice[2] = ag_solanago.Meta(destinationTokenAccount)
	return inst
}

// GetDestinationTokenAccountAccount gets the "destination_token_account" account.
func (inst *TokenTransferHook) GetDestinationTokenAccountAccount() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(2)
}

// SetOwnerAccount sets the "owner" account.
func (inst *TokenTransferHook) SetOwnerAccount(owner ag_solanago.PublicKey) *TokenTransferHook {
	inst.AccountMetaSlice[3] = ag_solanago.Meta(owner)
	return inst
}

// GetOwnerAccount gets the "owner" account.
func (inst *TokenTransferHook) GetOwnerAccount() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(3)
}

// SetExtraAccountMetaListAccount sets the "extra_account_meta_list" account.
func (inst *TokenTransferHook) SetExtraAccountMetaListAccount(extraAccountMetaList ag_solanago.PublicKey) *TokenTransferHook {
	inst.AccountMetaSlice[4] = ag_solanago.Meta(extraAccountMetaList)
	return inst
}

func (inst *TokenTransferHook) findFindExtraAccountMetaListAddress(receiptTokenMint ag_solanago.PublicKey, knownBumpSeed uint8) (pda ag_solanago.PublicKey, bumpSeed uint8, err error) {
	var seeds [][]byte
	// const: extra-account-metas
	seeds = append(seeds, []byte{byte(0x65), byte(0x78), byte(0x74), byte(0x72), byte(0x61), byte(0x2d), byte(0x61), byte(0x63), byte(0x63), byte(0x6f), byte(0x75), byte(0x6e), byte(0x74), byte(0x2d), byte(0x6d), byte(0x65), byte(0x74), byte(0x61), byte(0x73)})
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

// FindExtraAccountMetaListAddressWithBumpSeed calculates ExtraAccountMetaList account address with given seeds and a known bump seed.
func (inst *TokenTransferHook) FindExtraAccountMetaListAddressWithBumpSeed(receiptTokenMint ag_solanago.PublicKey, bumpSeed uint8) (pda ag_solanago.PublicKey, err error) {
	pda, _, err = inst.findFindExtraAccountMetaListAddress(receiptTokenMint, bumpSeed)
	return
}

func (inst *TokenTransferHook) MustFindExtraAccountMetaListAddressWithBumpSeed(receiptTokenMint ag_solanago.PublicKey, bumpSeed uint8) (pda ag_solanago.PublicKey) {
	pda, _, err := inst.findFindExtraAccountMetaListAddress(receiptTokenMint, bumpSeed)
	if err != nil {
		panic(err)
	}
	return
}

// FindExtraAccountMetaListAddress finds ExtraAccountMetaList account address with given seeds.
func (inst *TokenTransferHook) FindExtraAccountMetaListAddress(receiptTokenMint ag_solanago.PublicKey) (pda ag_solanago.PublicKey, bumpSeed uint8, err error) {
	pda, bumpSeed, err = inst.findFindExtraAccountMetaListAddress(receiptTokenMint, 0)
	return
}

func (inst *TokenTransferHook) MustFindExtraAccountMetaListAddress(receiptTokenMint ag_solanago.PublicKey) (pda ag_solanago.PublicKey) {
	pda, _, err := inst.findFindExtraAccountMetaListAddress(receiptTokenMint, 0)
	if err != nil {
		panic(err)
	}
	return
}

// GetExtraAccountMetaListAccount gets the "extra_account_meta_list" account.
func (inst *TokenTransferHook) GetExtraAccountMetaListAccount() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(4)
}

// SetFundAccount sets the "fund" account.
func (inst *TokenTransferHook) SetFundAccount(fund ag_solanago.PublicKey) *TokenTransferHook {
	inst.AccountMetaSlice[5] = ag_solanago.Meta(fund).WRITE()
	return inst
}

func (inst *TokenTransferHook) findFindFundAddress(receiptTokenMint ag_solanago.PublicKey, knownBumpSeed uint8) (pda ag_solanago.PublicKey, bumpSeed uint8, err error) {
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
func (inst *TokenTransferHook) FindFundAddressWithBumpSeed(receiptTokenMint ag_solanago.PublicKey, bumpSeed uint8) (pda ag_solanago.PublicKey, err error) {
	pda, _, err = inst.findFindFundAddress(receiptTokenMint, bumpSeed)
	return
}

func (inst *TokenTransferHook) MustFindFundAddressWithBumpSeed(receiptTokenMint ag_solanago.PublicKey, bumpSeed uint8) (pda ag_solanago.PublicKey) {
	pda, _, err := inst.findFindFundAddress(receiptTokenMint, bumpSeed)
	if err != nil {
		panic(err)
	}
	return
}

// FindFundAddress finds Fund account address with given seeds.
func (inst *TokenTransferHook) FindFundAddress(receiptTokenMint ag_solanago.PublicKey) (pda ag_solanago.PublicKey, bumpSeed uint8, err error) {
	pda, bumpSeed, err = inst.findFindFundAddress(receiptTokenMint, 0)
	return
}

func (inst *TokenTransferHook) MustFindFundAddress(receiptTokenMint ag_solanago.PublicKey) (pda ag_solanago.PublicKey) {
	pda, _, err := inst.findFindFundAddress(receiptTokenMint, 0)
	if err != nil {
		panic(err)
	}
	return
}

// GetFundAccount gets the "fund" account.
func (inst *TokenTransferHook) GetFundAccount() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(5)
}

func (inst TokenTransferHook) Build() *Instruction {
	return &Instruction{BaseVariant: ag_binary.BaseVariant{
		Impl:   inst,
		TypeID: Instruction_TokenTransferHook,
	}}
}

// ValidateAndBuild validates the instruction parameters and accounts;
// if there is a validation error, it returns the error.
// Otherwise, it builds and returns the instruction.
func (inst TokenTransferHook) ValidateAndBuild() (*Instruction, error) {
	if err := inst.Validate(); err != nil {
		return nil, err
	}
	return inst.Build(), nil
}

func (inst *TokenTransferHook) Validate() error {
	// Check whether all (required) parameters are set:
	{
		if inst.Amount == nil {
			return errors.New("Amount parameter is not set")
		}
	}

	// Check whether all (required) accounts are set:
	{
		if inst.AccountMetaSlice[0] == nil {
			return errors.New("accounts.SourceTokenAccount is not set")
		}
		if inst.AccountMetaSlice[1] == nil {
			return errors.New("accounts.ReceiptTokenMint is not set")
		}
		if inst.AccountMetaSlice[2] == nil {
			return errors.New("accounts.DestinationTokenAccount is not set")
		}
		if inst.AccountMetaSlice[3] == nil {
			return errors.New("accounts.Owner is not set")
		}
		if inst.AccountMetaSlice[4] == nil {
			return errors.New("accounts.ExtraAccountMetaList is not set")
		}
		if inst.AccountMetaSlice[5] == nil {
			return errors.New("accounts.Fund is not set")
		}
	}
	return nil
}

func (inst *TokenTransferHook) EncodeToTree(parent ag_treeout.Branches) {
	parent.Child(ag_format.Program(ProgramName, ProgramID)).
		//
		ParentFunc(func(programBranch ag_treeout.Branches) {
			programBranch.Child(ag_format.Instruction("TokenTransferHook")).
				//
				ParentFunc(func(instructionBranch ag_treeout.Branches) {

					// Parameters of the instruction:
					instructionBranch.Child("Params[len=1]").ParentFunc(func(paramsBranch ag_treeout.Branches) {
						paramsBranch.Child(ag_format.Param("Amount", *inst.Amount))
					})

					// Accounts of the instruction:
					instructionBranch.Child("Accounts[len=6]").ParentFunc(func(accountsBranch ag_treeout.Branches) {
						accountsBranch.Child(ag_format.Meta("          source_token_", inst.AccountMetaSlice.Get(0)))
						accountsBranch.Child(ag_format.Meta("     receipt_token_mint", inst.AccountMetaSlice.Get(1)))
						accountsBranch.Child(ag_format.Meta("     destination_token_", inst.AccountMetaSlice.Get(2)))
						accountsBranch.Child(ag_format.Meta("                  owner", inst.AccountMetaSlice.Get(3)))
						accountsBranch.Child(ag_format.Meta("extra_account_meta_list", inst.AccountMetaSlice.Get(4)))
						accountsBranch.Child(ag_format.Meta("                   fund", inst.AccountMetaSlice.Get(5)))
					})
				})
		})
}

func (obj TokenTransferHook) MarshalWithEncoder(encoder *ag_binary.Encoder) (err error) {
	// Serialize `Amount` param:
	err = encoder.Encode(obj.Amount)
	if err != nil {
		return err
	}
	return nil
}
func (obj *TokenTransferHook) UnmarshalWithDecoder(decoder *ag_binary.Decoder) (err error) {
	// Deserialize `Amount`:
	err = decoder.Decode(&obj.Amount)
	if err != nil {
		return err
	}
	return nil
}

// NewTokenTransferHookInstruction declares a new TokenTransferHook instruction with the provided parameters and accounts.
func NewTokenTransferHookInstruction(
	// Parameters:
	amount uint64,
	// Accounts:
	sourceTokenAccount ag_solanago.PublicKey,
	receiptTokenMint ag_solanago.PublicKey,
	destinationTokenAccount ag_solanago.PublicKey,
	owner ag_solanago.PublicKey,
	extraAccountMetaList ag_solanago.PublicKey,
	fund ag_solanago.PublicKey) *TokenTransferHook {
	return NewTokenTransferHookInstructionBuilder().
		SetAmount(amount).
		SetSourceTokenAccountAccount(sourceTokenAccount).
		SetReceiptTokenMintAccount(receiptTokenMint).
		SetDestinationTokenAccountAccount(destinationTokenAccount).
		SetOwnerAccount(owner).
		SetExtraAccountMetaListAccount(extraAccountMetaList).
		SetFundAccount(fund)
}
