// Code generated by https://github.com/gagliardetto/anchor-go. DO NOT EDIT.

package restaking

import (
	"errors"
	ag_binary "github.com/gagliardetto/binary"
	ag_solanago "github.com/gagliardetto/solana-go"
	ag_format "github.com/gagliardetto/solana-go/text/format"
	ag_treeout "github.com/gagliardetto/treeout"
)

// FundDepositToken is the `fund_deposit_token` instruction.
type FundDepositToken struct {
	Amount   *uint64
	Metadata *Metadata `bin:"optional"`

	// [0] = [WRITE, SIGNER] user
	//
	// [1] = [WRITE] user_receipt
	//
	// [2] = [WRITE] fund
	//
	// [3] = [WRITE] fund_token_authority
	//
	// [4] = [WRITE] receipt_token_mint
	//
	// [5] = [WRITE] receipt_token_account
	//
	// [6] = [WRITE] token_mint
	//
	// [7] = [WRITE] user_token_account
	//
	// [8] = [WRITE] fund_token_account
	//
	// [9] = [] token_pricing_source_0
	//
	// [10] = [] token_pricing_source_1
	//
	// [11] = [] instruction_sysvar
	//
	// [12] = [] deposit_token_program
	//
	// [13] = [] receipt_token_program
	//
	// [14] = [] associated_token_program
	//
	// [15] = [] system_program
	ag_solanago.AccountMetaSlice `bin:"-"`
}

// NewFundDepositTokenInstructionBuilder creates a new `FundDepositToken` instruction builder.
func NewFundDepositTokenInstructionBuilder() *FundDepositToken {
	nd := &FundDepositToken{
		AccountMetaSlice: make(ag_solanago.AccountMetaSlice, 16),
	}
	nd.AccountMetaSlice[4] = ag_solanago.Meta(ag_solanago.MustPublicKeyFromBase58("FRAGsJAbW4cHk2DYhtAWohV6MUMauJHCFtT1vGvRwnXN")).WRITE()
	nd.AccountMetaSlice[9] = ag_solanago.Meta(ag_solanago.MustPublicKeyFromBase58("azFVdHtAJN8BX3sbGAYkXvtdjdrT5U6rj9rovvUFos9"))
	nd.AccountMetaSlice[10] = ag_solanago.Meta(ag_solanago.MustPublicKeyFromBase58("8szGkuLTAux9XMgZ2vtY39jVSowEcpBfFfD8hXSEqdGC"))
	nd.AccountMetaSlice[11] = ag_solanago.Meta(ag_solanago.MustPublicKeyFromBase58("Sysvar1nstructions1111111111111111111111111"))
	nd.AccountMetaSlice[13] = ag_solanago.Meta(ag_solanago.MustPublicKeyFromBase58("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"))
	nd.AccountMetaSlice[14] = ag_solanago.Meta(ag_solanago.MustPublicKeyFromBase58("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"))
	nd.AccountMetaSlice[15] = ag_solanago.Meta(ag_solanago.MustPublicKeyFromBase58("11111111111111111111111111111111"))
	return nd
}

// SetAmount sets the "amount" parameter.
func (inst *FundDepositToken) SetAmount(amount uint64) *FundDepositToken {
	inst.Amount = &amount
	return inst
}

// SetMetadata sets the "metadata" parameter.
func (inst *FundDepositToken) SetMetadata(metadata Metadata) *FundDepositToken {
	inst.Metadata = &metadata
	return inst
}

// SetUserAccount sets the "user" account.
func (inst *FundDepositToken) SetUserAccount(user ag_solanago.PublicKey) *FundDepositToken {
	inst.AccountMetaSlice[0] = ag_solanago.Meta(user).WRITE().SIGNER()
	return inst
}

// GetUserAccount gets the "user" account.
func (inst *FundDepositToken) GetUserAccount() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(0)
}

// SetUserReceiptAccount sets the "user_receipt" account.
func (inst *FundDepositToken) SetUserReceiptAccount(userReceipt ag_solanago.PublicKey) *FundDepositToken {
	inst.AccountMetaSlice[1] = ag_solanago.Meta(userReceipt).WRITE()
	return inst
}

func (inst *FundDepositToken) findFindUserReceiptAddress(user ag_solanago.PublicKey, receiptTokenMint ag_solanago.PublicKey, knownBumpSeed uint8) (pda ag_solanago.PublicKey, bumpSeed uint8, err error) {
	var seeds [][]byte
	// const: user_receipt_seed
	seeds = append(seeds, []byte{byte(0x75), byte(0x73), byte(0x65), byte(0x72), byte(0x5f), byte(0x72), byte(0x65), byte(0x63), byte(0x65), byte(0x69), byte(0x70), byte(0x74), byte(0x5f), byte(0x73), byte(0x65), byte(0x65), byte(0x64)})
	// path: user
	seeds = append(seeds, user.Bytes())
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

// FindUserReceiptAddressWithBumpSeed calculates UserReceipt account address with given seeds and a known bump seed.
func (inst *FundDepositToken) FindUserReceiptAddressWithBumpSeed(user ag_solanago.PublicKey, receiptTokenMint ag_solanago.PublicKey, bumpSeed uint8) (pda ag_solanago.PublicKey, err error) {
	pda, _, err = inst.findFindUserReceiptAddress(user, receiptTokenMint, bumpSeed)
	return
}

func (inst *FundDepositToken) MustFindUserReceiptAddressWithBumpSeed(user ag_solanago.PublicKey, receiptTokenMint ag_solanago.PublicKey, bumpSeed uint8) (pda ag_solanago.PublicKey) {
	pda, _, err := inst.findFindUserReceiptAddress(user, receiptTokenMint, bumpSeed)
	if err != nil {
		panic(err)
	}
	return
}

// FindUserReceiptAddress finds UserReceipt account address with given seeds.
func (inst *FundDepositToken) FindUserReceiptAddress(user ag_solanago.PublicKey, receiptTokenMint ag_solanago.PublicKey) (pda ag_solanago.PublicKey, bumpSeed uint8, err error) {
	pda, bumpSeed, err = inst.findFindUserReceiptAddress(user, receiptTokenMint, 0)
	return
}

func (inst *FundDepositToken) MustFindUserReceiptAddress(user ag_solanago.PublicKey, receiptTokenMint ag_solanago.PublicKey) (pda ag_solanago.PublicKey) {
	pda, _, err := inst.findFindUserReceiptAddress(user, receiptTokenMint, 0)
	if err != nil {
		panic(err)
	}
	return
}

// GetUserReceiptAccount gets the "user_receipt" account.
func (inst *FundDepositToken) GetUserReceiptAccount() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(1)
}

// SetFundAccount sets the "fund" account.
func (inst *FundDepositToken) SetFundAccount(fund ag_solanago.PublicKey) *FundDepositToken {
	inst.AccountMetaSlice[2] = ag_solanago.Meta(fund).WRITE()
	return inst
}

func (inst *FundDepositToken) findFindFundAddress(receiptTokenMint ag_solanago.PublicKey, knownBumpSeed uint8) (pda ag_solanago.PublicKey, bumpSeed uint8, err error) {
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
func (inst *FundDepositToken) FindFundAddressWithBumpSeed(receiptTokenMint ag_solanago.PublicKey, bumpSeed uint8) (pda ag_solanago.PublicKey, err error) {
	pda, _, err = inst.findFindFundAddress(receiptTokenMint, bumpSeed)
	return
}

func (inst *FundDepositToken) MustFindFundAddressWithBumpSeed(receiptTokenMint ag_solanago.PublicKey, bumpSeed uint8) (pda ag_solanago.PublicKey) {
	pda, _, err := inst.findFindFundAddress(receiptTokenMint, bumpSeed)
	if err != nil {
		panic(err)
	}
	return
}

// FindFundAddress finds Fund account address with given seeds.
func (inst *FundDepositToken) FindFundAddress(receiptTokenMint ag_solanago.PublicKey) (pda ag_solanago.PublicKey, bumpSeed uint8, err error) {
	pda, bumpSeed, err = inst.findFindFundAddress(receiptTokenMint, 0)
	return
}

func (inst *FundDepositToken) MustFindFundAddress(receiptTokenMint ag_solanago.PublicKey) (pda ag_solanago.PublicKey) {
	pda, _, err := inst.findFindFundAddress(receiptTokenMint, 0)
	if err != nil {
		panic(err)
	}
	return
}

// GetFundAccount gets the "fund" account.
func (inst *FundDepositToken) GetFundAccount() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(2)
}

// SetFundTokenAuthorityAccount sets the "fund_token_authority" account.
func (inst *FundDepositToken) SetFundTokenAuthorityAccount(fundTokenAuthority ag_solanago.PublicKey) *FundDepositToken {
	inst.AccountMetaSlice[3] = ag_solanago.Meta(fundTokenAuthority).WRITE()
	return inst
}

func (inst *FundDepositToken) findFindFundTokenAuthorityAddress(receiptTokenMint ag_solanago.PublicKey, knownBumpSeed uint8) (pda ag_solanago.PublicKey, bumpSeed uint8, err error) {
	var seeds [][]byte
	// const: fund_token_authority_seed
	seeds = append(seeds, []byte{byte(0x66), byte(0x75), byte(0x6e), byte(0x64), byte(0x5f), byte(0x74), byte(0x6f), byte(0x6b), byte(0x65), byte(0x6e), byte(0x5f), byte(0x61), byte(0x75), byte(0x74), byte(0x68), byte(0x6f), byte(0x72), byte(0x69), byte(0x74), byte(0x79), byte(0x5f), byte(0x73), byte(0x65), byte(0x65), byte(0x64)})
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

// FindFundTokenAuthorityAddressWithBumpSeed calculates FundTokenAuthority account address with given seeds and a known bump seed.
func (inst *FundDepositToken) FindFundTokenAuthorityAddressWithBumpSeed(receiptTokenMint ag_solanago.PublicKey, bumpSeed uint8) (pda ag_solanago.PublicKey, err error) {
	pda, _, err = inst.findFindFundTokenAuthorityAddress(receiptTokenMint, bumpSeed)
	return
}

func (inst *FundDepositToken) MustFindFundTokenAuthorityAddressWithBumpSeed(receiptTokenMint ag_solanago.PublicKey, bumpSeed uint8) (pda ag_solanago.PublicKey) {
	pda, _, err := inst.findFindFundTokenAuthorityAddress(receiptTokenMint, bumpSeed)
	if err != nil {
		panic(err)
	}
	return
}

// FindFundTokenAuthorityAddress finds FundTokenAuthority account address with given seeds.
func (inst *FundDepositToken) FindFundTokenAuthorityAddress(receiptTokenMint ag_solanago.PublicKey) (pda ag_solanago.PublicKey, bumpSeed uint8, err error) {
	pda, bumpSeed, err = inst.findFindFundTokenAuthorityAddress(receiptTokenMint, 0)
	return
}

func (inst *FundDepositToken) MustFindFundTokenAuthorityAddress(receiptTokenMint ag_solanago.PublicKey) (pda ag_solanago.PublicKey) {
	pda, _, err := inst.findFindFundTokenAuthorityAddress(receiptTokenMint, 0)
	if err != nil {
		panic(err)
	}
	return
}

// GetFundTokenAuthorityAccount gets the "fund_token_authority" account.
func (inst *FundDepositToken) GetFundTokenAuthorityAccount() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(3)
}

// SetReceiptTokenMintAccount sets the "receipt_token_mint" account.
func (inst *FundDepositToken) SetReceiptTokenMintAccount(receiptTokenMint ag_solanago.PublicKey) *FundDepositToken {
	inst.AccountMetaSlice[4] = ag_solanago.Meta(receiptTokenMint).WRITE()
	return inst
}

// GetReceiptTokenMintAccount gets the "receipt_token_mint" account.
func (inst *FundDepositToken) GetReceiptTokenMintAccount() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(4)
}

// SetReceiptTokenAccountAccount sets the "receipt_token_account" account.
func (inst *FundDepositToken) SetReceiptTokenAccountAccount(receiptTokenAccount ag_solanago.PublicKey) *FundDepositToken {
	inst.AccountMetaSlice[5] = ag_solanago.Meta(receiptTokenAccount).WRITE()
	return inst
}

func (inst *FundDepositToken) findFindReceiptTokenAccountAddress(user ag_solanago.PublicKey, receiptTokenProgram ag_solanago.PublicKey, receiptTokenMint ag_solanago.PublicKey, knownBumpSeed uint8) (pda ag_solanago.PublicKey, bumpSeed uint8, err error) {
	var seeds [][]byte
	// path: user
	seeds = append(seeds, user.Bytes())
	// path: receiptTokenProgram
	seeds = append(seeds, receiptTokenProgram.Bytes())
	// path: receiptTokenMint
	seeds = append(seeds, receiptTokenMint.Bytes())

	programID := ag_solanago.PublicKey([]byte{byte(0x8c), byte(0x97), byte(0x25), byte(0x8f), byte(0x4e), byte(0x24), byte(0x89), byte(0xf1), byte(0xbb), byte(0x3d), byte(0x10), byte(0x29), byte(0x14), byte(0x8e), byte(0xd), byte(0x83), byte(0xb), byte(0x5a), byte(0x13), byte(0x99), byte(0xda), byte(0xff), byte(0x10), byte(0x84), byte(0x4), byte(0x8e), byte(0x7b), byte(0xd8), byte(0xdb), byte(0xe9), byte(0xf8), byte(0x59)})

	if knownBumpSeed != 0 {
		seeds = append(seeds, []byte{byte(bumpSeed)})
		pda, err = ag_solanago.CreateProgramAddress(seeds, programID)
	} else {
		pda, bumpSeed, err = ag_solanago.FindProgramAddress(seeds, programID)
	}
	return
}

// FindReceiptTokenAccountAddressWithBumpSeed calculates ReceiptTokenAccount account address with given seeds and a known bump seed.
func (inst *FundDepositToken) FindReceiptTokenAccountAddressWithBumpSeed(user ag_solanago.PublicKey, receiptTokenProgram ag_solanago.PublicKey, receiptTokenMint ag_solanago.PublicKey, bumpSeed uint8) (pda ag_solanago.PublicKey, err error) {
	pda, _, err = inst.findFindReceiptTokenAccountAddress(user, receiptTokenProgram, receiptTokenMint, bumpSeed)
	return
}

func (inst *FundDepositToken) MustFindReceiptTokenAccountAddressWithBumpSeed(user ag_solanago.PublicKey, receiptTokenProgram ag_solanago.PublicKey, receiptTokenMint ag_solanago.PublicKey, bumpSeed uint8) (pda ag_solanago.PublicKey) {
	pda, _, err := inst.findFindReceiptTokenAccountAddress(user, receiptTokenProgram, receiptTokenMint, bumpSeed)
	if err != nil {
		panic(err)
	}
	return
}

// FindReceiptTokenAccountAddress finds ReceiptTokenAccount account address with given seeds.
func (inst *FundDepositToken) FindReceiptTokenAccountAddress(user ag_solanago.PublicKey, receiptTokenProgram ag_solanago.PublicKey, receiptTokenMint ag_solanago.PublicKey) (pda ag_solanago.PublicKey, bumpSeed uint8, err error) {
	pda, bumpSeed, err = inst.findFindReceiptTokenAccountAddress(user, receiptTokenProgram, receiptTokenMint, 0)
	return
}

func (inst *FundDepositToken) MustFindReceiptTokenAccountAddress(user ag_solanago.PublicKey, receiptTokenProgram ag_solanago.PublicKey, receiptTokenMint ag_solanago.PublicKey) (pda ag_solanago.PublicKey) {
	pda, _, err := inst.findFindReceiptTokenAccountAddress(user, receiptTokenProgram, receiptTokenMint, 0)
	if err != nil {
		panic(err)
	}
	return
}

// GetReceiptTokenAccountAccount gets the "receipt_token_account" account.
func (inst *FundDepositToken) GetReceiptTokenAccountAccount() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(5)
}

// SetTokenMintAccount sets the "token_mint" account.
func (inst *FundDepositToken) SetTokenMintAccount(tokenMint ag_solanago.PublicKey) *FundDepositToken {
	inst.AccountMetaSlice[6] = ag_solanago.Meta(tokenMint).WRITE()
	return inst
}

// GetTokenMintAccount gets the "token_mint" account.
func (inst *FundDepositToken) GetTokenMintAccount() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(6)
}

// SetUserTokenAccountAccount sets the "user_token_account" account.
func (inst *FundDepositToken) SetUserTokenAccountAccount(userTokenAccount ag_solanago.PublicKey) *FundDepositToken {
	inst.AccountMetaSlice[7] = ag_solanago.Meta(userTokenAccount).WRITE()
	return inst
}

// GetUserTokenAccountAccount gets the "user_token_account" account.
func (inst *FundDepositToken) GetUserTokenAccountAccount() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(7)
}

// SetFundTokenAccountAccount sets the "fund_token_account" account.
func (inst *FundDepositToken) SetFundTokenAccountAccount(fundTokenAccount ag_solanago.PublicKey) *FundDepositToken {
	inst.AccountMetaSlice[8] = ag_solanago.Meta(fundTokenAccount).WRITE()
	return inst
}

func (inst *FundDepositToken) findFindFundTokenAccountAddress(fundTokenAuthority ag_solanago.PublicKey, depositTokenProgram ag_solanago.PublicKey, tokenMint ag_solanago.PublicKey, knownBumpSeed uint8) (pda ag_solanago.PublicKey, bumpSeed uint8, err error) {
	var seeds [][]byte
	// path: fundTokenAuthority
	seeds = append(seeds, fundTokenAuthority.Bytes())
	// path: depositTokenProgram
	seeds = append(seeds, depositTokenProgram.Bytes())
	// path: tokenMint
	seeds = append(seeds, tokenMint.Bytes())

	programID := ag_solanago.PublicKey([]byte{byte(0x8c), byte(0x97), byte(0x25), byte(0x8f), byte(0x4e), byte(0x24), byte(0x89), byte(0xf1), byte(0xbb), byte(0x3d), byte(0x10), byte(0x29), byte(0x14), byte(0x8e), byte(0xd), byte(0x83), byte(0xb), byte(0x5a), byte(0x13), byte(0x99), byte(0xda), byte(0xff), byte(0x10), byte(0x84), byte(0x4), byte(0x8e), byte(0x7b), byte(0xd8), byte(0xdb), byte(0xe9), byte(0xf8), byte(0x59)})

	if knownBumpSeed != 0 {
		seeds = append(seeds, []byte{byte(bumpSeed)})
		pda, err = ag_solanago.CreateProgramAddress(seeds, programID)
	} else {
		pda, bumpSeed, err = ag_solanago.FindProgramAddress(seeds, programID)
	}
	return
}

// FindFundTokenAccountAddressWithBumpSeed calculates FundTokenAccount account address with given seeds and a known bump seed.
func (inst *FundDepositToken) FindFundTokenAccountAddressWithBumpSeed(fundTokenAuthority ag_solanago.PublicKey, depositTokenProgram ag_solanago.PublicKey, tokenMint ag_solanago.PublicKey, bumpSeed uint8) (pda ag_solanago.PublicKey, err error) {
	pda, _, err = inst.findFindFundTokenAccountAddress(fundTokenAuthority, depositTokenProgram, tokenMint, bumpSeed)
	return
}

func (inst *FundDepositToken) MustFindFundTokenAccountAddressWithBumpSeed(fundTokenAuthority ag_solanago.PublicKey, depositTokenProgram ag_solanago.PublicKey, tokenMint ag_solanago.PublicKey, bumpSeed uint8) (pda ag_solanago.PublicKey) {
	pda, _, err := inst.findFindFundTokenAccountAddress(fundTokenAuthority, depositTokenProgram, tokenMint, bumpSeed)
	if err != nil {
		panic(err)
	}
	return
}

// FindFundTokenAccountAddress finds FundTokenAccount account address with given seeds.
func (inst *FundDepositToken) FindFundTokenAccountAddress(fundTokenAuthority ag_solanago.PublicKey, depositTokenProgram ag_solanago.PublicKey, tokenMint ag_solanago.PublicKey) (pda ag_solanago.PublicKey, bumpSeed uint8, err error) {
	pda, bumpSeed, err = inst.findFindFundTokenAccountAddress(fundTokenAuthority, depositTokenProgram, tokenMint, 0)
	return
}

func (inst *FundDepositToken) MustFindFundTokenAccountAddress(fundTokenAuthority ag_solanago.PublicKey, depositTokenProgram ag_solanago.PublicKey, tokenMint ag_solanago.PublicKey) (pda ag_solanago.PublicKey) {
	pda, _, err := inst.findFindFundTokenAccountAddress(fundTokenAuthority, depositTokenProgram, tokenMint, 0)
	if err != nil {
		panic(err)
	}
	return
}

// GetFundTokenAccountAccount gets the "fund_token_account" account.
func (inst *FundDepositToken) GetFundTokenAccountAccount() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(8)
}

// SetTokenPricingSource0Account sets the "token_pricing_source_0" account.
func (inst *FundDepositToken) SetTokenPricingSource0Account(tokenPricingSource0 ag_solanago.PublicKey) *FundDepositToken {
	inst.AccountMetaSlice[9] = ag_solanago.Meta(tokenPricingSource0)
	return inst
}

// GetTokenPricingSource0Account gets the "token_pricing_source_0" account.
func (inst *FundDepositToken) GetTokenPricingSource0Account() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(9)
}

// SetTokenPricingSource1Account sets the "token_pricing_source_1" account.
func (inst *FundDepositToken) SetTokenPricingSource1Account(tokenPricingSource1 ag_solanago.PublicKey) *FundDepositToken {
	inst.AccountMetaSlice[10] = ag_solanago.Meta(tokenPricingSource1)
	return inst
}

// GetTokenPricingSource1Account gets the "token_pricing_source_1" account.
func (inst *FundDepositToken) GetTokenPricingSource1Account() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(10)
}

// SetInstructionSysvarAccount sets the "instruction_sysvar" account.
func (inst *FundDepositToken) SetInstructionSysvarAccount(instructionSysvar ag_solanago.PublicKey) *FundDepositToken {
	inst.AccountMetaSlice[11] = ag_solanago.Meta(instructionSysvar)
	return inst
}

// GetInstructionSysvarAccount gets the "instruction_sysvar" account (optional).
func (inst *FundDepositToken) GetInstructionSysvarAccount() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(11)
}

// SetDepositTokenProgramAccount sets the "deposit_token_program" account.
func (inst *FundDepositToken) SetDepositTokenProgramAccount(depositTokenProgram ag_solanago.PublicKey) *FundDepositToken {
	inst.AccountMetaSlice[12] = ag_solanago.Meta(depositTokenProgram)
	return inst
}

// GetDepositTokenProgramAccount gets the "deposit_token_program" account.
func (inst *FundDepositToken) GetDepositTokenProgramAccount() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(12)
}

// SetReceiptTokenProgramAccount sets the "receipt_token_program" account.
func (inst *FundDepositToken) SetReceiptTokenProgramAccount(receiptTokenProgram ag_solanago.PublicKey) *FundDepositToken {
	inst.AccountMetaSlice[13] = ag_solanago.Meta(receiptTokenProgram)
	return inst
}

// GetReceiptTokenProgramAccount gets the "receipt_token_program" account.
func (inst *FundDepositToken) GetReceiptTokenProgramAccount() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(13)
}

// SetAssociatedTokenProgramAccount sets the "associated_token_program" account.
func (inst *FundDepositToken) SetAssociatedTokenProgramAccount(associatedTokenProgram ag_solanago.PublicKey) *FundDepositToken {
	inst.AccountMetaSlice[14] = ag_solanago.Meta(associatedTokenProgram)
	return inst
}

// GetAssociatedTokenProgramAccount gets the "associated_token_program" account.
func (inst *FundDepositToken) GetAssociatedTokenProgramAccount() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(14)
}

// SetSystemProgramAccount sets the "system_program" account.
func (inst *FundDepositToken) SetSystemProgramAccount(systemProgram ag_solanago.PublicKey) *FundDepositToken {
	inst.AccountMetaSlice[15] = ag_solanago.Meta(systemProgram)
	return inst
}

// GetSystemProgramAccount gets the "system_program" account.
func (inst *FundDepositToken) GetSystemProgramAccount() *ag_solanago.AccountMeta {
	return inst.AccountMetaSlice.Get(15)
}

func (inst FundDepositToken) Build() *Instruction {
	return &Instruction{BaseVariant: ag_binary.BaseVariant{
		Impl:   inst,
		TypeID: Instruction_FundDepositToken,
	}}
}

// ValidateAndBuild validates the instruction parameters and accounts;
// if there is a validation error, it returns the error.
// Otherwise, it builds and returns the instruction.
func (inst FundDepositToken) ValidateAndBuild() (*Instruction, error) {
	if err := inst.Validate(); err != nil {
		return nil, err
	}
	return inst.Build(), nil
}

func (inst *FundDepositToken) Validate() error {
	// Check whether all (required) parameters are set:
	{
		if inst.Amount == nil {
			return errors.New("Amount parameter is not set")
		}
	}

	// Check whether all (required) accounts are set:
	{
		if inst.AccountMetaSlice[0] == nil {
			return errors.New("accounts.User is not set")
		}
		if inst.AccountMetaSlice[1] == nil {
			return errors.New("accounts.UserReceipt is not set")
		}
		if inst.AccountMetaSlice[2] == nil {
			return errors.New("accounts.Fund is not set")
		}
		if inst.AccountMetaSlice[3] == nil {
			return errors.New("accounts.FundTokenAuthority is not set")
		}
		if inst.AccountMetaSlice[4] == nil {
			return errors.New("accounts.ReceiptTokenMint is not set")
		}
		if inst.AccountMetaSlice[5] == nil {
			return errors.New("accounts.ReceiptTokenAccount is not set")
		}
		if inst.AccountMetaSlice[6] == nil {
			return errors.New("accounts.TokenMint is not set")
		}
		if inst.AccountMetaSlice[7] == nil {
			return errors.New("accounts.UserTokenAccount is not set")
		}
		if inst.AccountMetaSlice[8] == nil {
			return errors.New("accounts.FundTokenAccount is not set")
		}
		if inst.AccountMetaSlice[9] == nil {
			return errors.New("accounts.TokenPricingSource0 is not set")
		}
		if inst.AccountMetaSlice[10] == nil {
			return errors.New("accounts.TokenPricingSource1 is not set")
		}

		// [11] = InstructionSysvar is optional

		if inst.AccountMetaSlice[12] == nil {
			return errors.New("accounts.DepositTokenProgram is not set")
		}
		if inst.AccountMetaSlice[13] == nil {
			return errors.New("accounts.ReceiptTokenProgram is not set")
		}
		if inst.AccountMetaSlice[14] == nil {
			return errors.New("accounts.AssociatedTokenProgram is not set")
		}
		if inst.AccountMetaSlice[15] == nil {
			return errors.New("accounts.SystemProgram is not set")
		}
	}
	return nil
}

func (inst *FundDepositToken) EncodeToTree(parent ag_treeout.Branches) {
	parent.Child(ag_format.Program(ProgramName, ProgramID)).
		//
		ParentFunc(func(programBranch ag_treeout.Branches) {
			programBranch.Child(ag_format.Instruction("FundDepositToken")).
				//
				ParentFunc(func(instructionBranch ag_treeout.Branches) {

					// Parameters of the instruction:
					instructionBranch.Child("Params[len=2]").ParentFunc(func(paramsBranch ag_treeout.Branches) {
						paramsBranch.Child(ag_format.Param("  Amount", *inst.Amount))
						paramsBranch.Child(ag_format.Param("Metadata (OPT)", inst.Metadata))
					})

					// Accounts of the instruction:
					instructionBranch.Child("Accounts[len=16]").ParentFunc(func(accountsBranch ag_treeout.Branches) {
						accountsBranch.Child(ag_format.Meta("                    user", inst.AccountMetaSlice.Get(0)))
						accountsBranch.Child(ag_format.Meta("            user_receipt", inst.AccountMetaSlice.Get(1)))
						accountsBranch.Child(ag_format.Meta("                    fund", inst.AccountMetaSlice.Get(2)))
						accountsBranch.Child(ag_format.Meta("    fund_token_authority", inst.AccountMetaSlice.Get(3)))
						accountsBranch.Child(ag_format.Meta("      receipt_token_mint", inst.AccountMetaSlice.Get(4)))
						accountsBranch.Child(ag_format.Meta("          receipt_token_", inst.AccountMetaSlice.Get(5)))
						accountsBranch.Child(ag_format.Meta("              token_mint", inst.AccountMetaSlice.Get(6)))
						accountsBranch.Child(ag_format.Meta("             user_token_", inst.AccountMetaSlice.Get(7)))
						accountsBranch.Child(ag_format.Meta("             fund_token_", inst.AccountMetaSlice.Get(8)))
						accountsBranch.Child(ag_format.Meta("  token_pricing_source_0", inst.AccountMetaSlice.Get(9)))
						accountsBranch.Child(ag_format.Meta("  token_pricing_source_1", inst.AccountMetaSlice.Get(10)))
						accountsBranch.Child(ag_format.Meta("      instruction_sysvar", inst.AccountMetaSlice.Get(11)))
						accountsBranch.Child(ag_format.Meta("   deposit_token_program", inst.AccountMetaSlice.Get(12)))
						accountsBranch.Child(ag_format.Meta("   receipt_token_program", inst.AccountMetaSlice.Get(13)))
						accountsBranch.Child(ag_format.Meta("associated_token_program", inst.AccountMetaSlice.Get(14)))
						accountsBranch.Child(ag_format.Meta("          system_program", inst.AccountMetaSlice.Get(15)))
					})
				})
		})
}

func (obj FundDepositToken) MarshalWithEncoder(encoder *ag_binary.Encoder) (err error) {
	// Serialize `Amount` param:
	err = encoder.Encode(obj.Amount)
	if err != nil {
		return err
	}
	// Serialize `Metadata` param (optional):
	{
		if obj.Metadata == nil {
			err = encoder.WriteBool(false)
			if err != nil {
				return err
			}
		} else {
			err = encoder.WriteBool(true)
			if err != nil {
				return err
			}
			err = encoder.Encode(obj.Metadata)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
func (obj *FundDepositToken) UnmarshalWithDecoder(decoder *ag_binary.Decoder) (err error) {
	// Deserialize `Amount`:
	err = decoder.Decode(&obj.Amount)
	if err != nil {
		return err
	}
	// Deserialize `Metadata` (optional):
	{
		ok, err := decoder.ReadBool()
		if err != nil {
			return err
		}
		if ok {
			err = decoder.Decode(&obj.Metadata)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// NewFundDepositTokenInstruction declares a new FundDepositToken instruction with the provided parameters and accounts.
func NewFundDepositTokenInstruction(
	// Parameters:
	amount uint64,
	metadata Metadata,
	// Accounts:
	user ag_solanago.PublicKey,
	userReceipt ag_solanago.PublicKey,
	fund ag_solanago.PublicKey,
	fundTokenAuthority ag_solanago.PublicKey,
	receiptTokenMint ag_solanago.PublicKey,
	receiptTokenAccount ag_solanago.PublicKey,
	tokenMint ag_solanago.PublicKey,
	userTokenAccount ag_solanago.PublicKey,
	fundTokenAccount ag_solanago.PublicKey,
	tokenPricingSource0 ag_solanago.PublicKey,
	tokenPricingSource1 ag_solanago.PublicKey,
	instructionSysvar ag_solanago.PublicKey,
	depositTokenProgram ag_solanago.PublicKey,
	receiptTokenProgram ag_solanago.PublicKey,
	associatedTokenProgram ag_solanago.PublicKey,
	systemProgram ag_solanago.PublicKey) *FundDepositToken {
	return NewFundDepositTokenInstructionBuilder().
		SetAmount(amount).
		SetMetadata(metadata).
		SetUserAccount(user).
		SetUserReceiptAccount(userReceipt).
		SetFundAccount(fund).
		SetFundTokenAuthorityAccount(fundTokenAuthority).
		SetReceiptTokenMintAccount(receiptTokenMint).
		SetReceiptTokenAccountAccount(receiptTokenAccount).
		SetTokenMintAccount(tokenMint).
		SetUserTokenAccountAccount(userTokenAccount).
		SetFundTokenAccountAccount(fundTokenAccount).
		SetTokenPricingSource0Account(tokenPricingSource0).
		SetTokenPricingSource1Account(tokenPricingSource1).
		SetInstructionSysvarAccount(instructionSysvar).
		SetDepositTokenProgramAccount(depositTokenProgram).
		SetReceiptTokenProgramAccount(receiptTokenProgram).
		SetAssociatedTokenProgramAccount(associatedTokenProgram).
		SetSystemProgramAccount(systemProgram)
}
