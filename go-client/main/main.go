package main

import (
	"github.com/celer-network/cbridge-cowa/go-client"
	"github.com/celer-network/goutils/log"
	"github.com/ethereum/go-ethereum/common"
)

func main() {
	log.Infof("test cowa client")
	cfg := &client.CosConfig{
		ChainId:              999999997,
		RawChainID:           "injective-888",
		Key:                  "demoacc",
		AccountPrefix:        "inj",
		Endpoint:             "https://testnet.tm.injective.network:443",
		BridgeAddr:           "fdaaf34776d29faf81ffa96c941f2ae934d0db51",
		VaultBridgeAddr:      "3208622742955b341c5b183e199630c7d0038f4e",
		PegBridgeAddr:        "4bbe3676dc736742f7e617c7ab197bed603218d0",
		MsgPackage:           "cosmwasm.wasm.v1",
		KeyringBackend:       "file",
		TransactorPassphrase: "12341234",
		GasAdjustment:        1.5,
		GasPrices:            "50000000000inj",
		Timeout:              "15s",
		HomeDir:              "/Users/liuxiao/code/sgn-v2-ops/node-configs/sgn-testnet-4000/sentinel/",
	}

	cc := client.NewCosClient(cfg)
	if cc == nil {
		log.Fatalln("fail to init cos client")
	}

	blkTs, err := cc.GetBlockTs()
	if err != nil {
		log.Fatalln(err)
	}
	log.Infof("cur blk ts:%s", blkTs.String())

	testPauseFlow(cc)
	//testQueryDelay(cc)
	//testExecuteDelay(cc)
	//testQueryVolCap(cc)
	//testQuerySupply(cc)
	//testQueryCW20(cc)
	//testQueryPegTokenBalance(cc)
	//testQueryNativeToken(cc)
}

func testQueryNativeToken(cc *client.CosClient) {
	coin, err := cc.QueryNativeToken("17467394ef21ce1180F989Df2BB3f1b3f984433D")
	if err != nil {
		log.Fatalln(err)
	}
	log.Infof("inj balance: %s", coin.Amount.String())

}

func testQueryPegTokenBalance(cc *client.CosClient) {
	bal, err := cc.QueryCW20Balance("588Fb670809Da351372569f64604683bCD39d9f2", "17467394ef21ce1180F989Df2BB3f1b3f984433D")
	if err != nil {
		log.Fatalln(err)
	}
	log.Infof("bal: %+v", bal)
}

func testQueryCW20(cc *client.CosClient) {
	_, err := cc.QueryCW20Balance("588Fb670809Da351372569f64604683bCD39d9f2", "17467394ef21ce1180F989Df2BB3f1b3f984433D")
	if err != nil {
		log.Fatalln(err)
	}
}

func testQuerySupply(cc *client.CosClient) {
	pegSupply, err := cc.QueryPegTokenSupply("588Fb670809Da351372569f64604683bCD39d9f2")
	if err != nil {
		log.Fatalln(err)
	}
	log.Infof("peg mint supply:%s", pegSupply.String())

	_, err = cc.QueryTokenTotalSupply("588Fb670809Da351372569f64604683bCD39d9f2")
	if err != nil {
		log.Fatalln(err)
	}
}

func testQueryVolCap(cc *client.CosClient) {
	vaultVolumeEpochLength, err := cc.QueryVaultVolumeEpochLength()
	if err != nil {
		log.Fatalln(err)
	}
	log.Infof("vaultVolumeEpochLength: %d", vaultVolumeEpochLength)

	pegVolumeEpochLength, err := cc.QueryPegBridgeVolumeEpochLength()
	if err != nil {
		log.Fatalln(err)
	}
	log.Infof("pegVolumeEpochLength: %d", pegVolumeEpochLength)
}

func testExecuteDelay(cc *client.CosClient) {
	txhash, err := cc.ExecutePegBridgeDelay(common.HexToHash("11280a01283fafb5b6e53155d84e5749c6412ecdb745c314eda447efa56cba03"))
	if err != nil {
		log.Fatalln(err)
	}
	log.Infof("execute delay, txhash:%s", txhash)
}

func testQueryDelay(cc *client.CosClient) {
	dt, err := cc.GetVaultDelayThreshold("588Fb670809Da351372569f64604683bCD39d9f2")
	if err != nil {
		log.Fatalln(err)
	}
	log.Infof("vault delay threshold, dt:%s", dt)

	dt, err = cc.GetPegBridgeDelayThreshold("588Fb670809Da351372569f64604683bCD39d9f2")
	if err != nil {
		log.Fatalln(err)
	}
	log.Infof("vault delay threshold, dt:%s", dt)

	mintExist, err := cc.QueryPegBridgeRecordExist(common.HexToHash("11280a01283fafb5b6e53155d84e5749c6412ecdb745c314eda447efa56cba03"), false)
	if err != nil {
		log.Fatalln(err)
	}
	log.Infof("mint exist, %v", mintExist)

	depositExist, err := cc.QueryVaultRecordExist(common.HexToHash("f26dd5c0278dfeb3954ff950045745f25f0f88614b1c15a638290a6453529e3e"), true)
	if err != nil {
		log.Fatalln(err)
	}
	log.Infof("deposit exist, %v", depositExist)

	vaultDelayPeriod, err := cc.GetVaultDelayPeriod()
	if err != nil {
		log.Fatalln(err)
	}
	log.Infof("vault delay period, %v", vaultDelayPeriod)

	peggedDelayPeriod, err := cc.GetPegBridgeDelayPeriod()
	if err != nil {
		log.Fatalln(err)
	}
	log.Infof("pegged delay period, %v", peggedDelayPeriod)

	mintDelayExist, err := cc.PegBridgeDelayTransferExist(common.HexToHash("11280a01283fafb5b6e53155d84e5749c6412ecdb745c314eda447efa56cba03"))
	if err != nil {
		log.Fatalln(err)
	}
	log.Infof("mint delay exist, %v", mintDelayExist)
}

func testPauseFlow(cc *client.CosClient) {
	paused, err := cc.IsPaused(cc.VaultAddr)
	if err != nil {
		log.Fatalln(err)
	}
	log.Infof("pause status: %v", paused)

	if !paused {
		txHash, err := cc.Pause(cc.VaultAddr)
		if err != nil {
			log.Fatalln(err)
		}
		log.Infof("pause txHash: %s", txHash)
	}

	paused, err = cc.IsPaused(cc.VaultAddr)
	if err != nil {
		log.Fatalln(err)
	}
	log.Infof("pause status: %v", paused)

	if paused {
		txHash, err := cc.Unpause(cc.VaultAddr)
		if err != nil {
			log.Fatalln(err)
		}
		log.Infof("unpause txHash: %s", txHash)
	}
}
