package types

import (
	"context"
	"encoding/json"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
	lens "github.com/strangelove-ventures/lens/client"
)

// RawContractMessage defines a json message that is sent or returned by a wasm contract.
// This type can hold any type of bytes. Until validateBasic is called there should not be
// any assumptions made that the data is valid syntax or semantic.
type RawContractMessage []byte

//func (r RawContractMessage) MarshalJSON() ([]byte, error) {
//	return json.RawMessage(r).MarshalJSON()
//}
//
//func (r *RawContractMessage) UnmarshalJSON(b []byte) error {
//	if r == nil {
//		return fmt.Errorf("unmarshalJSON on nil pointer")
//	}
//	*r = append((*r)[0:0], b...)
//	return nil
//}

func (r *RawContractMessage) ValidateBasic() error {
	if r == nil {
		return fmt.Errorf("empty message")
	}
	if !json.Valid(*r) {
		return fmt.Errorf("invalid message")
	}
	return nil
}

// Bytes returns raw bytes type
func (r RawContractMessage) Bytes() []byte {
	return r
}

func SmartContractState(cc *lens.ChainClient, msgPackage string, in *QuerySmartContractStateRequest) (*QuerySmartContractStateResponse, error) {
	out := new(QuerySmartContractStateResponse)
	err := cc.Invoke(context.Background(), "/"+msgPackage+".Query/SmartContractState", in, out, nil)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func BankBalance(cc *lens.ChainClient, msgPackage string, in *QueryBalanceRequest) (*QueryBalanceResponse, error) {
	out := new(QueryBalanceResponse)
	err := cc.Invoke(context.Background(), "/"+msgPackage+".Query/Balance", in, out, nil)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func ChainSigners(cc *lens.ChainClient, contractAddr sdk.AccAddress, msgPackage string) (*WasmQueryResponseSigners, error) {
	out := new(WasmQueryResponseSigners)
	msgbz, _ := json.Marshal(&WasmQueryRequestSigners{})
	req := &QuerySmartContractStateRequest{
		Address:   cc.MustEncodeAccAddr(contractAddr),
		QueryData: msgbz,
	}
	resp, err := SmartContractState(cc, msgPackage, req)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(resp.Data, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func QueryOTVRecord(cc *lens.ChainClient, contractAddr sdk.AccAddress, id string, is_deposit bool, msgPackage string) (*WasmQueryOTVRecordResponse, error) {
	out := new(WasmQueryOTVRecordResponse)
	queryMsg, _ := json.Marshal(&WasmQueryOTVRecordRequest{Record: OTVRecord{Id: id, IsDeposit: is_deposit}})
	req := &QuerySmartContractStateRequest{
		Address:   cc.MustEncodeAccAddr(contractAddr),
		QueryData: queryMsg,
	}
	resp, err := SmartContractState(cc, msgPackage, req)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(resp.Data, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func QueryPTBRecord(cc *lens.ChainClient, contractAddr sdk.AccAddress, id string, is_burn bool, msgPackage string) (*WasmQueryPTBRecordResponse, error) {
	out := new(WasmQueryPTBRecordResponse)
	queryMsg, _ := json.Marshal(&WasmQueryPTBRecordRequest{Record: PTBRecord{Id: id, IsBurn: is_burn}})
	req := &QuerySmartContractStateRequest{
		Address:   cc.MustEncodeAccAddr(contractAddr),
		QueryData: queryMsg,
	}
	resp, err := SmartContractState(cc, msgPackage, req)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(resp.Data, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}
