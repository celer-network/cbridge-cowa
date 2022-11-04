package types

import (
	"encoding/json"

	"github.com/cosmos/cosmos-sdk/codec"
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

// ensure Msg interface compliance at compile time
var (
	_ sdk.Msg = &MsgExecuteContract{}
)

// wasm message types
const (
	RouterKey                  = "wasm"
	TypeMsgStoreCode           = "store_code"
	TypeMsgInstantiateContract = "instantiate_contract"
	TypeMsgExecuteContract     = "execute_contract"
	EnforcedMaxContractMsgSize = uint64(20 * 1024) // 10KB
)

var (
	ModuleCdc = codec.NewProtoCodec(cdctypes.NewInterfaceRegistry())
)

// NewMsgStoreCode creates a MsgStoreCode instance
func NewMsgStoreCode(sender sdk.AccAddress, wasmByteCode []byte) *MsgStoreCode {
	return &MsgStoreCode{
		Sender:       sender.String(),
		WASMByteCode: wasmByteCode,
	}
}

// Route implements sdk.Msg
func (msg MsgStoreCode) Route() string { return RouterKey }

// Type implements sdk.Msg
func (msg MsgStoreCode) Type() string { return TypeMsgStoreCode }

// GetSignBytes Implements Msg
func (msg MsgStoreCode) GetSignBytes() []byte {
	return sdk.MustSortJSON(ModuleCdc.MustMarshalJSON(&msg))
}

// GetSigners Implements Msg
func (msg MsgStoreCode) GetSigners() []sdk.AccAddress {
	sender, err := sdk.GetFromBech32(msg.Sender, msg.SenderPrefix)
	if err != nil {
		panic(err)
	}

	return []sdk.AccAddress{sender}
}

// ValidateBasic Implements sdk.Msg
func (msg MsgStoreCode) ValidateBasic() error {
	_, err := sdk.GetFromBech32(msg.Sender, msg.SenderPrefix)
	if err != nil {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "Invalid sender address (%s)", err)
	}

	if len(msg.WASMByteCode) == 0 {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "empty wasm code")
	}

	if uint64(len(msg.WASMByteCode)) > EnforcedMaxContractMsgSize {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "wasm code too large")
	}

	return nil
}

// NewMsgInstantiateContract creates a MsgInstantiateContract instance
func NewMsgInstantiateContract(sender, admin sdk.AccAddress, codeID uint64, initMsg []byte, initCoins sdk.Coins) *MsgInstantiateContract {
	var adminAddr string
	if !admin.Empty() {
		adminAddr = admin.String()
	}

	return &MsgInstantiateContract{
		Sender:    sender.String(),
		Admin:     adminAddr,
		CodeID:    codeID,
		InitMsg:   initMsg,
		InitCoins: initCoins,
	}
}

// Route implements sdk.Msg
func (msg MsgInstantiateContract) Route() string {
	return RouterKey
}

// Type implements sdk.Msg
func (msg MsgInstantiateContract) Type() string {
	return TypeMsgInstantiateContract
}

// ValidateBasic implements sdk.Msg
func (msg MsgInstantiateContract) ValidateBasic() error {
	_, err := sdk.GetFromBech32(msg.Sender, msg.SenderPrefix)
	if err != nil {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "Invalid sender address (%s)", err)
	}

	if len(msg.Admin) != 0 {
		_, err := sdk.AccAddressFromBech32(msg.Admin)
		if err != nil {
			return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "Invalid admin address (%s)", err)
		}
	}

	if !msg.InitCoins.IsValid() {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, msg.InitCoins.String())
	}

	if uint64(len(msg.InitMsg)) > EnforcedMaxContractMsgSize {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "wasm msg byte size is too huge")
	}

	if !json.Valid(msg.InitMsg) {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "wasm msg byte format is invalid json")
	}

	return nil
}

// GetSignBytes implements sdk.Msg
func (msg MsgInstantiateContract) GetSignBytes() []byte {
	return sdk.MustSortJSON(ModuleCdc.MustMarshalJSON(&msg))
}

// GetSigners implements sdk.Msg
func (msg MsgInstantiateContract) GetSigners() []sdk.AccAddress {
	sender, err := sdk.GetFromBech32(msg.Sender, msg.SenderPrefix)
	if err != nil {
		panic(err)
	}

	return []sdk.AccAddress{sender}
}

// NewMsgExecuteContract creates a NewMsgExecuteContract instance
func NewMsgExecuteContract(sender sdk.AccAddress, contract sdk.AccAddress, execMsg []byte, coins sdk.Coins) *MsgExecuteContract {
	return &MsgExecuteContract{
		Sender:     sender.String(),
		Contract:   contract.String(),
		ExecuteMsg: execMsg,
		Coins:      coins,
	}
}

// Route implements sdk.Msg
func (msg MsgExecuteContract) Route() string {
	return RouterKey
}

// Type implements sdk.Msg
func (msg MsgExecuteContract) Type() string {
	return TypeMsgExecuteContract
}

// ValidateBasic implements sdk.Msg
func (msg MsgExecuteContract) ValidateBasic() error {
	_, err := sdk.GetFromBech32(msg.Sender, msg.SenderPrefix)
	if err != nil {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "Invalid sender address (%s)", err)
	}

	_, err = sdk.GetFromBech32(msg.Contract, msg.SenderPrefix)
	if err != nil {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "Invalid contract address (%s)", err)
	}

	if !msg.Coins.IsValid() {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, msg.Coins.String())
	}

	if uint64(len(msg.ExecuteMsg)) > EnforcedMaxContractMsgSize {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "wasm msg byte size is too huge")
	}

	if !json.Valid(msg.ExecuteMsg) {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "wasm msg byte format is invalid json")
	}

	return nil
}

// GetSignBytes implements sdk.Msg
func (msg MsgExecuteContract) GetSignBytes() []byte {
	return sdk.MustSortJSON(ModuleCdc.MustMarshalJSON(&msg))
}

// GetSigners implements sdk.Msg
func (msg MsgExecuteContract) GetSigners() []sdk.AccAddress {
	sender, err := sdk.GetFromBech32(msg.Sender, msg.SenderPrefix)
	if err != nil {
		panic(err)
	}

	return []sdk.AccAddress{sender}
}
