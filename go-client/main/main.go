package main

import (
	"github.com/celer-network/cbridge-cowa/go-client"
	"github.com/celer-network/goutils/log"
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
		HomeDir:              "../home_config/",
	}

	cc := client.NewCosClient(cfg)
	if cc == nil {
		log.Fatalln("fail to init cos client")
	}

	testPauseFlow(cc)

	/*txHash, err := cc.Unpause("0x78167721f3f0bd7c20c4c783db10b95cc1207d5b980c02fc252b4825b9c87b2")
	if err != nil {
		log.Fatalln(err)
	}
	log.Infof("unpause txHash: %x", txHash)

	paused, err = cc.IsPaused("0x78167721f3f0bd7c20c4c783db10b95cc1207d5b980c02fc252b4825b9c87b2")
	if err != nil {
		log.Fatalln(err)
	}
	log.Infof("pause status: %v", paused)*/
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
