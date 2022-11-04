package client

import (
	"fmt"
	ec "github.com/ethereum/go-ethereum/common"
	"math/big"
)

type CosEventLog struct {
	TxHash ec.Hash `json:"tx_hash"`
	Height uint64  `json:"height"`
	Type   string  `json:"type"`
	Data   []byte  `json:"data"`
}

type CosVaultDeposited struct {
	DepositId   ec.Hash  `json:"dep_id"`
	Depositor   []byte   `json:"depositor"`
	Token       []byte   `json:"token"`
	Amount      *big.Int `json:"amount"`
	MintChainId uint64   `json:"mint_chain_id"`
	MintAccount []byte   `json:"mint_acct"`
}

type CosVaultWithdrawn struct {
	WithdrawId  ec.Hash  `json:"wd_id"`
	Receiver    []byte   `json:"receiver"`
	Token       []byte   `json:"token"`
	Amount      *big.Int `json:"amount"`
	RefChainId  uint64   `json:"ref_chain_id"`
	RefId       ec.Hash  `json:"ref_od"`
	BurnAccount []byte   `json:"burn_acct"`
}

type CosPegBridgeBurn struct {
	BurnId    ec.Hash  `json:"burn_id"`
	Burner    []byte   `json:"burner"`
	Token     []byte   `json:"token"`
	Amount    *big.Int `json:"amount"`
	ToChainId uint64   `json:"to_chain_id"`
	ToAccount []byte   `json:"to_acct"`
}

type CosPegBridgeMint struct {
	MintId     ec.Hash  `json:"mint_id"`
	Receiver   []byte   `json:"receiver"`
	Token      []byte   `json:"token"`
	Amount     *big.Int `json:"amount"`
	RefChainId uint64   `json:"ref_chain_id"`
	RefId      ec.Hash  `json:"ref_id"`
	Depositor  []byte   `json:"depositor"`
}

type WasmExecuteMsgWithdraw struct {
	Withdraw WasmExecuteMsgWithdrawBody `json:"withdraw"`
}

type WasmExecuteMsgWithdrawBody struct {
	Pbmsg string   `json:"pbmsg"` //base64 encoded string
	Sigs  []string `json:"sigs"`  //base64 encoded string
}

type WasmExecuteMsgMint struct {
	Mint WasmExecuteMsgMintBody `json:"mint"`
}

type WasmExecuteMsgMintBody struct {
	Pbmsg string   `json:"pbmsg"` //base64 encoded string
	Sigs  []string `json:"sigs"`  //base64 encoded string
}

type CosBridgeSignersUpdated struct {
	Signers []ec.Address
	Powers  []*big.Int
}

func (s CosBridgeSignersUpdated) String() interface{} {
	var out string
	for i, addr := range s.Signers {
		out += fmt.Sprintf("<addr %x power %s> ", addr, s.Powers[i])
	}
	return fmt.Sprintf("< %s>", out)
}

type WasmQueryRequestSigners struct {
	ChainSigners ChainSignersRequest `json:"chain_signers"`
}

type ChainSignersRequest struct{}

type WasmQueryResponseSigners struct {
	Signers [][]byte `json:"signers"`
	Powers  []string `json:"powers"`
}

type WasmQueryOTVRecordRequest struct {
	Record OTVRecord `json:"record"`
}

type OTVRecord struct {
	Id        string `json:"id"`
	IsDeposit bool   `json:"is_deposit"`
}

type WasmQueryOTVRecordResponse bool

type WasmQueryPTBRecordRequest struct {
	Record PTBRecord `json:"record"`
}

type PTBRecord struct {
	Id     string `json:"id"`
	IsBurn bool   `json:"is_burn"`
}

type WasmQueryPTBRecordResponse bool

type WasmExecuteMsgUpdateSigners struct {
	UpdateSigners WasmExecuteMsgUpdateSignersBody `json:"update_signers"`
}

type WasmExecuteMsgUpdateSignersBody struct {
	TriggerTime uint64
	Signers     []ec.Address
	Powers      []*big.Int
	Sigs        [][]byte
}
