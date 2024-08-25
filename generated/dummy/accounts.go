// Code generated by https://github.com/gagliardetto/anchor-go. DO NOT EDIT.

package dummy

import (
	"fmt"
	ag_binary "github.com/gagliardetto/binary"
	ag_solanago "github.com/gagliardetto/solana-go"
)

type AccountDataAccount struct {
	Data      VersionedData
	Owner     ag_solanago.PublicKey
	CreatedAt int64
}

var AccountDataAccountDiscriminator = [8]byte{23, 205, 88, 172, 233, 226, 180, 239}

func (obj AccountDataAccount) MarshalWithEncoder(encoder *ag_binary.Encoder) (err error) {
	// Write account discriminator:
	err = encoder.WriteBytes(AccountDataAccountDiscriminator[:], false)
	if err != nil {
		return err
	}
	// Serialize `Data` param:
	{
		tmp := versionedDataContainer{}
		switch realvalue := obj.Data.(type) {
		case *VersionedDataV1Tuple:
			tmp.Enum = 0
			tmp.V1 = *realvalue
		case *VersionedDataV2Tuple:
			tmp.Enum = 1
			tmp.V2 = *realvalue
		}
		err := encoder.Encode(tmp)
		if err != nil {
			return err
		}
	}
	// Serialize `Owner` param:
	err = encoder.Encode(obj.Owner)
	if err != nil {
		return err
	}
	// Serialize `CreatedAt` param:
	err = encoder.Encode(obj.CreatedAt)
	if err != nil {
		return err
	}
	return nil
}

func (obj *AccountDataAccount) UnmarshalWithDecoder(decoder *ag_binary.Decoder) (err error) {
	// Read and check account discriminator:
	{
		discriminator, err := decoder.ReadTypeID()
		if err != nil {
			return err
		}
		if !discriminator.Equal(AccountDataAccountDiscriminator[:]) {
			return fmt.Errorf(
				"wrong discriminator: wanted %s, got %s",
				"[23 205 88 172 233 226 180 239]",
				fmt.Sprint(discriminator[:]))
		}
	}
	// Deserialize `Data`:
	{
		tmp := new(versionedDataContainer)
		err := decoder.Decode(tmp)
		if err != nil {
			return err
		}
		switch tmp.Enum {
		case 0:
			obj.Data = &tmp.V1
		case 1:
			obj.Data = &tmp.V2
		default:
			return fmt.Errorf("unknown enum index: %v", tmp.Enum)
		}
	}
	// Deserialize `Owner`:
	err = decoder.Decode(&obj.Owner)
	if err != nil {
		return err
	}
	// Deserialize `CreatedAt`:
	err = decoder.Decode(&obj.CreatedAt)
	if err != nil {
		return err
	}
	return nil
}

type UserTokenAmountAccount struct {
	User   ag_solanago.PublicKey
	Bump   uint8
	Token  string
	Amount uint64
}

var UserTokenAmountAccountDiscriminator = [8]byte{126, 248, 226, 129, 204, 69, 113, 125}

func (obj UserTokenAmountAccount) MarshalWithEncoder(encoder *ag_binary.Encoder) (err error) {
	// Write account discriminator:
	err = encoder.WriteBytes(UserTokenAmountAccountDiscriminator[:], false)
	if err != nil {
		return err
	}
	// Serialize `User` param:
	err = encoder.Encode(obj.User)
	if err != nil {
		return err
	}
	// Serialize `Bump` param:
	err = encoder.Encode(obj.Bump)
	if err != nil {
		return err
	}
	// Serialize `Token` param:
	err = encoder.Encode(obj.Token)
	if err != nil {
		return err
	}
	// Serialize `Amount` param:
	err = encoder.Encode(obj.Amount)
	if err != nil {
		return err
	}
	return nil
}

func (obj *UserTokenAmountAccount) UnmarshalWithDecoder(decoder *ag_binary.Decoder) (err error) {
	// Read and check account discriminator:
	{
		discriminator, err := decoder.ReadTypeID()
		if err != nil {
			return err
		}
		if !discriminator.Equal(UserTokenAmountAccountDiscriminator[:]) {
			return fmt.Errorf(
				"wrong discriminator: wanted %s, got %s",
				"[126 248 226 129 204 69 113 125]",
				fmt.Sprint(discriminator[:]))
		}
	}
	// Deserialize `User`:
	err = decoder.Decode(&obj.User)
	if err != nil {
		return err
	}
	// Deserialize `Bump`:
	err = decoder.Decode(&obj.Bump)
	if err != nil {
		return err
	}
	// Deserialize `Token`:
	err = decoder.Decode(&obj.Token)
	if err != nil {
		return err
	}
	// Deserialize `Amount`:
	err = decoder.Decode(&obj.Amount)
	if err != nil {
		return err
	}
	return nil
}
