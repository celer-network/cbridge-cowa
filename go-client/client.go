package client

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/celer-network/cbridge-cowa/go-client/types"
	"github.com/celer-network/goutils/log"
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

type CosConfig struct {
	ChainId              uint64
	RawChainID           string
	Key                  string
	AccountPrefix        string
	Endpoint             string
	BridgeAddr           string
	PegBridgeAddr        string
	VaultBridgeAddr      string
	MsgPackage           string
	KeyringBackend       string
	TransactorPassphrase string
	GasAdjustment        float64
	GasPrices            string
	Timeout              string
	HomeDir              string
}

func NewCosClient(cfg *CosConfig) *CosClient {
	ret := &CosClient{
		ChainID:       cfg.ChainId,
		RawChainID:    cfg.RawChainID,
		BridgeAddr:    cfg.BridgeAddr,
		VaultAddr:     cfg.PegBridgeAddr,
		PegBridgeAddr: cfg.VaultBridgeAddr,
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
		RPCAddr:        cfg.Endpoint,
		AccountPrefix:  cfg.AccountPrefix,
		KeyringBackend: cfg.KeyringBackend,
		GasAdjustment:  cfg.GasAdjustment,
		GasPrices:      cfg.GasPrices,
		Debug:          true,
		Timeout:        cfg.Timeout,
		OutputFormat:   "json",
		SignModeStr:    "direct",
		Modules:        append([]module.AppModuleBasic{}, lens.ModuleBasics...),
	}

	reader := strings.NewReader(cfg.TransactorPassphrase + "\n")
	cc, err := lens.NewChainClient(chainClientConfig, cfg.HomeDir, reader, os.Stdout)
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

func (c *CosClient) isVaultPaused() (bool, error) {
	return c.IsPaused(c.VaultAddr)
}

func (c *CosClient) IsPegBridgePaused() (bool, error) {
	return c.IsPaused(c.PegBridgeAddr)
}

func (c *CosClient) IsPaused(contractCanonicalAddr string) (bool, error) {
	contractAddr, err := c.GetContractHumanAddress(contractCanonicalAddr)
	if err != nil {
		return false, err
	}
	request := &types.QuerySmartContractStateRequest{
		Address:   contractAddr,
		QueryData: []byte("{\"paused\":{}}"),
	}
	resp, err := types.SmartContractState(c.Cc, c.MsgPackage, request)
	if err != nil {
		return false, err
	}
	var paused bool
	err = json.Unmarshal(resp.Data, &paused)
	if err != nil {
		return false, err
	}
	return paused, nil
}

func (c *CosClient) PauseVault() (string, error) {
	return c.Pause(c.VaultAddr)
}

func (c *CosClient) PausePegBridge() (string, error) {
	return c.Pause(c.PegBridgeAddr)
}

func (c *CosClient) Pause(contractCanonicalAddr string) (string, error) {
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
	msg := &types.MsgExecuteContract{
		Sender:       senderAddr,
		Contract:     contractHumanAddr,
		ExecuteMsg:   []byte(`{"pause":{}}`),
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

func (c *CosClient) UnpauseVault() (string, error) {
	return c.Unpause(c.VaultAddr)
}

func (c *CosClient) UnpausePegBridge() (string, error) {
	return c.Unpause(c.PegBridgeAddr)
}

func (c *CosClient) Unpause(contractCanonicalAddr string) (string, error) {
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
	msg := &types.MsgExecuteContract{
		Sender:       senderAddr,
		Contract:     contractHumanAddr,
		ExecuteMsg:   []byte(`{"unpause":{}}`),
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

func (c *CosClient) QueryVaultRecordExist(id ec.Hash, isDeposit bool) (bool, error) {
	contractAddr, err := c.GetContractHumanAddress(c.VaultAddr)
	if err != nil {
		return false, err
	}
	request := &types.QuerySmartContractStateRequest{
		Address:   contractAddr,
		QueryData: []byte(fmt.Sprintf("{\"record\":{\"id\":\"%x\", \"is_deposit\":\"%t\"}}", id, isDeposit)),
	}
	_, err = types.SmartContractState(c.Cc, c.MsgPackage, request)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (c *CosClient) QueryPegBridgeRecordExist(id ec.Hash, isBurn bool) (bool, error) {
	contractAddr, err := c.GetContractHumanAddress(c.PegBridgeAddr)
	if err != nil {
		return false, err
	}
	request := &types.QuerySmartContractStateRequest{
		Address:   contractAddr,
		QueryData: []byte(fmt.Sprintf("{\"record\":{\"id\":\"%x\", \"is_burn\":\"%t\"}}", id, isBurn)),
	}
	_, err = types.SmartContractState(c.Cc, c.MsgPackage, request)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (c *CosClient) QueryVaultTokenVolume(token string) (*big.Int, error) {
	return c.QueryTokenVolume(token, c.VaultAddr)
}

func (c *CosClient) QueryPegBridgeTokenVolume(token string) (*big.Int, error) {
	return c.QueryTokenVolume(token, c.PegBridgeAddr)
}

func (c *CosClient) QueryTokenVolume(token string, contractCanonicalAddr string) (*big.Int, error) {
	contractAddr, err := c.GetContractHumanAddress(contractCanonicalAddr)
	if err != nil {
		return nil, err
	}
	request := &types.QuerySmartContractStateRequest{
		Address:   contractAddr,
		QueryData: []byte(fmt.Sprintf("{\"epoch_volume\":{\"token\":\"%s\"}}", token)),
	}
	resp, err := types.SmartContractState(c.Cc, c.MsgPackage, request)
	if err != nil {
		return nil, err
	}
	var volAmt string
	err = json.Unmarshal(resp.Data, &volAmt)
	if err != nil {
		return nil, err
	}
	vol, _ := new(big.Int).SetString(volAmt, 10)
	return vol, nil
}

func (c *CosClient) QueryVaultEpochVolumeCap(token string) (*big.Int, error) {
	return c.QueryEpochVolumeCap(token, c.VaultAddr)
}

func (c *CosClient) QueryPegbridgeEpochVolumeCap(token string) (*big.Int, error) {
	return c.QueryEpochVolumeCap(token, c.PegBridgeAddr)
}

func (c *CosClient) QueryEpochVolumeCap(token string, contractCanonicalAddr string) (*big.Int, error) {
	contractAddr, err := c.GetContractHumanAddress(contractCanonicalAddr)
	if err != nil {
		return nil, err
	}
	request := &types.QuerySmartContractStateRequest{
		Address:   contractAddr,
		QueryData: []byte(fmt.Sprintf("{\"epoch_volume_cap\":{\"token\":\"%s\"}}", token)),
	}
	resp, err := types.SmartContractState(c.Cc, c.MsgPackage, request)
	if err != nil {
		return nil, err
	}
	var volCapAmt string
	err = json.Unmarshal(resp.Data, &volCapAmt)
	if err != nil {
		return nil, err
	}
	volCap, _ := new(big.Int).SetString(volCapAmt, 10)
	return volCap, nil
}

func (c *CosClient) QueryVaultVolumeLastOpTimestamp(token string) (uint64, error) {
	return c.QueryVolumeLastOpTimestamp(token, c.VaultAddr)
}

func (c *CosClient) QueryPegBridgeVolumeLastOpTimestamp(token string) (uint64, error) {
	return c.QueryVolumeLastOpTimestamp(token, c.PegBridgeAddr)
}

func (c *CosClient) QueryVolumeLastOpTimestamp(token string, contractCanonicalAddr string) (uint64, error) {
	contractAddr, err := c.GetContractHumanAddress(contractCanonicalAddr)
	if err != nil {
		return 0, err
	}
	request := &types.QuerySmartContractStateRequest{
		Address:   contractAddr,
		QueryData: []byte(fmt.Sprintf("{\"last_op_timestamp\":{\"token\":\"%s\"}}", token)),
	}
	resp, err := types.SmartContractState(c.Cc, c.MsgPackage, request)
	if err != nil {
		return 0, err
	}
	var lastOpTimestamp uint64
	err = json.Unmarshal(resp.Data, &lastOpTimestamp)
	if err != nil {
		return 0, err
	}
	return lastOpTimestamp, nil
}

func (c *CosClient) QueryVaultVolumeEpochLength(token string) (uint64, error) {
	return c.QueryVolumeEpochLength(token, c.VaultAddr)
}

func (c *CosClient) QueryPegBridgeVolumeEpochLength(token string) (uint64, error) {
	return c.QueryVolumeEpochLength(token, c.PegBridgeAddr)
}

func (c *CosClient) QueryVolumeEpochLength(token string, contractCanonicalAddr string) (uint64, error) {
	contractAddr, err := c.GetContractHumanAddress(contractCanonicalAddr)
	if err != nil {
		return 0, err
	}
	request := &types.QuerySmartContractStateRequest{
		Address:   contractAddr,
		QueryData: []byte(fmt.Sprintf("{\"epoch_length\":{\"token\":\"%s\"}}", token)),
	}
	resp, err := types.SmartContractState(c.Cc, c.MsgPackage, request)
	if err != nil {
		return 0, err
	}
	var epochLength uint64
	err = json.Unmarshal(resp.Data, &epochLength)
	if err != nil {
		return 0, err
	}
	return epochLength, nil
}

func (c *CosClient) QueryTokenSupply(token string) (*big.Int, error) {
	return nil, nil
}

func (c *CosClient) QueryTxGasCost(txHash ec.Hash) (*big.Int, error) {
	return nil, nil
}

func (c *CosClient) QueryVaultBalance(token string) (*big.Int, error) {
	return nil, nil
}

func (c *CosClient) VaultDelayTransferExist(id ec.Hash) (bool, error) {
	return c.DelayTransferExist(id, c.VaultAddr)
}

func (c *CosClient) PegBridgeDelayTransferExist(id ec.Hash) (bool, error) {
	return c.DelayTransferExist(id, c.PegBridgeAddr)
}

func (c *CosClient) DelayTransferExist(id ec.Hash, contractCanonicalAddr string) (bool, error) {
	contractAddr, err := c.GetContractHumanAddress(contractCanonicalAddr)
	if err != nil {
		return false, err
	}
	request := &types.QuerySmartContractStateRequest{
		Address:   contractAddr,
		QueryData: []byte(fmt.Sprintf("{\"delayed_transfer\":{\"id\":\"%x\"}}", id)),
	}
	_, err = types.SmartContractState(c.Cc, c.MsgPackage, request)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (c *CosClient) GetVaultDelayThreshold() (int64, error) {
	return c.GetDelayThreshold(c.VaultAddr)
}

func (c *CosClient) GetPegBridgeDelayThreshold() (int64, error) {
	return c.GetDelayThreshold(c.PegBridgeAddr)
}

func (c *CosClient) GetDelayThreshold(contractCanonicalAddr string) (int64, error) {
	contractAddr, err := c.GetContractHumanAddress(contractCanonicalAddr)
	if err != nil {
		return 0, err
	}
	request := &types.QuerySmartContractStateRequest{
		Address:   contractAddr,
		QueryData: []byte("{\"delay_period\":{}}"),
	}
	resp, err := types.SmartContractState(c.Cc, c.MsgPackage, request)
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

func (c *CosClient) ExecuteVaultDelay(id ec.Hash) (string, error) {
	return c.ExecuteDelay(id, c.VaultAddr)
}

func (c *CosClient) ExecutePegBridgeDelay(id ec.Hash) (string, error) {
	return c.ExecuteDelay(id, c.PegBridgeAddr)
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
	msg := &types.MsgExecuteContract{
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
