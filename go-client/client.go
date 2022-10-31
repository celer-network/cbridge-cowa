package client

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/celer-network/goutils/log"
	"github.com/celer-network/sgn-v2/common"
	commontypes "github.com/celer-network/sgn-v2/common/types"
	cosmostypes "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	tmclient "github.com/cosmos/ibc-go/v2/modules/light-clients/07-tendermint/types"
	ec "github.com/ethereum/go-ethereum/common"
	lens "github.com/strangelove-ventures/lens/client"
	tmquery "github.com/tendermint/tendermint/libs/pubsub/query"
)

// all in one helper to do everything about cosmos chain
type CosClient struct {
	ChainID    uint64
	RawChainID string // the original cosmos chain id
	Cc         *lens.ChainClient

	BridgeAddr    string // cosmos canonical hex addr
	VaultAddr     string // cosmos canonical hex addr
	PegBridgeAddr string // cosmos canonical hex addr

	MsgPackage string // if provided, with replace the package of the Any typeUrl of the sdk.Msg
}

func NewCosClient(cfg *common.OneChainConfig, homeDir, keyringBackend, transactor_passphrase string) *CosClient {
	if !commontypes.IsCosChain(cfg.ChainID) {
		log.Fatalf("find invalid cosmos chainId:%d", cfg.ChainID)
	}

	ret := &CosClient{
		ChainID:       cfg.ChainID,
		RawChainID:    cfg.RawChainID,
		BridgeAddr:    cfg.CBridge,
		VaultAddr:     cfg.OTVault,
		PegBridgeAddr: cfg.PTBridge,
		MsgPackage:    cfg.MsgPackage,
	}

	if has0xPrefix(ret.BridgeAddr) {
		ret.BridgeAddr = ret.BridgeAddr[2:] // requires no 0x in cosmos sdk
	}
	if has0xPrefix(ret.VaultAddr) {
		ret.VaultAddr = ret.VaultAddr[2:]
	}
	if has0xPrefix(ret.PegBridgeAddr) {
		ret.PegBridgeAddr = ret.PegBridgeAddr[2:]
	}

	chainClientConfig := &lens.ChainClientConfig{
		Key:            cfg.Key,
		ChainID:        cfg.RawChainID,
		RPCAddr:        cfg.Gateway,
		AccountPrefix:  cfg.AccountPrefix,
		KeyringBackend: keyringBackend,
		GasAdjustment:  cfg.GasAdjustment,
		GasPrices:      cfg.GasPrices,
		Debug:          true,
		Timeout:        cfg.Timeout,
		OutputFormat:   "json",
		SignModeStr:    "direct",
		Modules:        append([]module.AppModuleBasic{}, lens.ModuleBasics...),
	}

	reader := strings.NewReader(transactor_passphrase + "\n")
	cc, err := lens.NewChainClient(chainClientConfig, homeDir, reader, os.Stdout)
	if err != nil {
		log.Fatalf("init chain client err: %s", err.Error())
	}
	err = cc.RPCClient.Start()
	if err != nil {
		log.Fatalf("start rpc client err: %s", err.Error())
	}
	ret.Cc = cc
	return ret
}

func has0xPrefix(str string) bool {
	return len(str) >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')
}

func (c *CosClient) Monitor(eventQuery string, handleEvents func(events map[string][]string), outCapacity ...int) error {
	res, err := c.Cc.RPCClient.Subscribe(context.Background(), "monitor", eventQuery, outCapacity...)

	if err != nil {
		log.Errorln("ws client subscribe error", err)
		return err
	}

	for e := range res {
		handleEvents(e.Events)
	}

	return nil
}

var (
	EventQuery = tmquery.MustParse("tm.event='Tx'").String()

	AndContractQueryParamTmpl = " AND wasm._contract_address='%s'"
)

func has(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}

func (c *CosClient) MonOTV(depositCallback, withdrawCallback, dtExectutedCallback func(events map[string][]string, chid uint64)) {
	if c.VaultAddr == "" {
		return
	}
	contractAddr, _ := cosmostypes.AccAddressFromHex(c.VaultAddr)
	log.Infof("start monitor cosmos chain original_token_vault, chainid: %s", c.RawChainID)
	err := c.Monitor(EventQuery+fmt.Sprintf(AndContractQueryParamTmpl, c.Cc.MustEncodeAccAddr(contractAddr)),
		func(events map[string][]string) {
			// todo: not sure if those three events would be strictly seperated by this monitor service, so parallel processing them at present.
			// event: deposited
			if has(events["wasm.action"], "deposit") && events["wasm.dst_chid"] != nil {
				log.Infof("Mon commos chain deposited:%+v, chainid: %s", events, c.RawChainID)
				depositCallback(events, c.ChainID)
			}
			// event: withdrawn
			if has(events["wasm.action"], "withdraw") && events["wasm.ref_chain_id"] != nil {
				log.Infof("Mon commos chain withdrawn:%+v, chainid: %s", events, c.RawChainID)
				withdrawCallback(events, c.ChainID)
			}
			// event: delayed withdraw executed
			if has(events["wasm.delayed_transfer_action"], "execute_delayed_transfer") && events["wasm.delayed_transfer_id"] != nil {
				log.Infof("Mon commos chain delayed withdraw executed:%+v, chainid: %s", events, c.RawChainID)
				dtExectutedCallback(events, c.ChainID)
			}
		})
	if err != nil {
		log.Fatalf("fail mon cosmos chain original_token_vault, err:%s", err.Error())
	}
}

func (c *CosClient) MonPTB(burnCallback, mintCallback, dtExecutedCallback func(events map[string][]string, chid uint64)) {
	if c.PegBridgeAddr == "" {
		return
	}
	contractAddr, _ := cosmostypes.AccAddressFromHex(c.PegBridgeAddr)
	log.Infof("start monitor cosmos chain pegged_token_bridge, chainid: %s", c.RawChainID)
	err := c.Monitor(EventQuery+fmt.Sprintf(AndContractQueryParamTmpl, c.Cc.MustEncodeAccAddr(contractAddr)),
		func(events map[string][]string) {
			// todo: not sure if those three events would be strictly seperated by this monitor service, so parallel processing them at present.
			// event: burn
			if has(events["wasm.action"], "burn") && events["wasm.to_chid"] != nil {
				log.Infof("Mon commos chain burn:%+v, chainid: %s", events, c.RawChainID)
				burnCallback(events, c.ChainID)
			}
			// event: mint
			if has(events["wasm.action"], "mint") && events["wasm.ref_chain_id"] != nil {
				log.Infof("Mon commos chain mint:%+v, chainid: %s", events, c.RawChainID)
				mintCallback(events, c.ChainID)
			}
			// event: delayed mint executed
			if has(events["wasm.delayed_transfer_action"], "execute_delayed_transfer") && events["wasm.delayed_transfer_id"] != nil {
				log.Infof("Mon commos chain delayed mint executed:%+v, chainid: %s", events, c.RawChainID)
				dtExecutedCallback(events, c.ChainID)
			}
		})
	if err != nil {
		log.Fatalf("fail mon cosmos chain pegged_token_bridge, err:%s", err.Error())
	}
}

func ToHex(b []byte) string {
	length := len(b)
	if length%2 == 1 {
		length++ //word length in oven
	}
	if length == 20 {
		return ec.BytesToAddress(b).Hex()
	}
	if length == 32 {
		return ec.BytesToHash(b).Hex()
	}
	return "0x" + ec.Bytes2Hex(b)
}

func (c *CosClient) GetBlockTs() (time.Time, error) {
	height, err := c.Cc.QueryLatestHeight()
	if err != nil {
		return time.Now(), err
	}
	header, err := c.Cc.QueryHeaderAtHeight(height)
	if err != nil {
		return time.Now(), err
	}

	h, ok := header.(*tmclient.Header)
	if ok {
		return h.Header.Time, nil
	} else {
		return time.Now(), fmt.Errorf("fail to get terra cur blk ts")
	}
}

func (c *CosClient) QuerySsHash() (ec.Hash, error) {
	return ec.Hash{}, nil
}

func (c *CosClient) PauseVault() error {
	return nil
}

func (c *CosClient) PausePegBridge() error {
	return nil
}

func (c *CosClient) QueryVaultRecordExist() (bool, error) {
	return false, nil
}

func (c *CosClient) QueryPegBridgeRecordExist() (bool, error) {
	return false, nil
}

func (c *CosClient) QueryPegBridgeCoinEpochVolume() (*big.Int, error) {
	return nil, nil
}

func (c *CosClient) QueryVaultTokenConfig() (*big.Int, *big.Int, *big.Int, *big.Int, error) {
	return nil, nil, nil, nil, nil
}

func (c *CosClient) QueryPegBridgeTokenConfig() (*big.Int, *big.Int, *big.Int, *big.Int, error) {
	return nil, nil, nil, nil, nil
}

func (c *CosClient) QueryTokenSupply() (*big.Int, error) {
	return nil, nil
}

func (c *CosClient) QueryVolumeLastOpTimestamp() (uint64, error) {
	return 0, nil
}

func (c *CosClient) QueryVolumeEpochLength() (uint64, error) {
	return 0, nil
}

func (c *CosClient) QueryTxGasCost() (*big.Int, error) {
	return nil, nil
}

func (c *CosClient) QueryVaultBalance() (*big.Int, error) {
	return nil, nil
}

func (c *CosClient) DelayTransferExist(id ec.Hash, contractCanonicalAddr string) (bool, error) {
	contractAddr, err := c.GetContractHumanAddress(contractCanonicalAddr)
	if err != nil {
		return false, err
	}
	request := &commontypes.QuerySmartContractStateRequest{
		Address:   contractAddr,
		QueryData: []byte(fmt.Sprintf("{\"delayed_transfer\":{\"id\":\"%x\"}}", id)),
	}
	_, err = commontypes.SmartContractState(c.Cc, c.MsgPackage, request)
	if err != nil {
		if strings.Contains(err.Error(), "DelayedXfer not found") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (c *CosClient) GetDelayThreshold(contractCanonicalAddr string) (int64, error) {
	contractAddr, err := c.GetContractHumanAddress(contractCanonicalAddr)
	if err != nil {
		return 0, err
	}
	request := &commontypes.QuerySmartContractStateRequest{
		Address:   contractAddr,
		QueryData: []byte("{\"delay_period\":{}}"),
	}
	resp, err := commontypes.SmartContractState(c.Cc, c.MsgPackage, request)
	if err != nil {
		return 0, err
	}
	var period int64
	err = json.Unmarshal(resp.Data, &period)
	if err != nil {
		return 0, err
	}
	return period, nil
}

func (c *CosClient) ExecuteDelay(id ec.Hash, contractCanonicalAddr string) (string, error) {
	contractHumanAddr, err := c.GetContractHumanAddress(contractCanonicalAddr)
	if err != nil {
		log.Errorf("err:%v", err)
		return "", err
	}
	senderAddr, err := c.Cc.Address()
	if err != nil {
		log.Errorf("err:%v", err)
		return "", err
	}
	msg := &commontypes.MsgExecuteContract{
		Sender:       senderAddr,
		Contract:     contractHumanAddr,
		ExecuteMsg:   []byte(fmt.Sprintf(`{"execute_delayed_transfer":{"id":"%x"}}`, id)),
		Coins:        nil,
		SenderPrefix: c.Cc.Config.AccountPrefix,
	}
	resp, err := c.Cc.SendMsgWithPackageName(context.Background(), msg, &c.MsgPackage)
	if err != nil {
		log.Errorf("err:%v", err)
		return "", err
	}
	return resp.TxHash, nil
}

func (c *CosClient) GetContractHumanAddress(contractCanonicalAddr string) (string, error) {
	addr, err := cosmostypes.AccAddressFromHex(c.VaultAddr)
	if err != nil {
		return "", err
	}
	return c.Cc.MustEncodeAccAddr(addr), nil
}
