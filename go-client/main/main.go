package main

import (
	"github.com/celer-network/cbridge-cowa/go-client"
	"github.com/celer-network/goutils/log"
)

func main() {
	log.Infof("test cowa client")
	cfg := &client.CosConfig{
		ChainId:              999999998,
		RawChainID:           "sei-devnet-1",
		Key:                  "demoacc",
		AccountPrefix:        "sei",
		Endpoint:             "http://34.223.104.208:26654",
		BridgeAddr:           "0x9e28beafa966b2407bffb0d48651e94972a56e69f3c0897d9e8facbdaeb98386",
		VaultBridgeAddr:      "0x78167721f3f0bd57c20c4c783db10b95cc1207d5b980c02fc252b4825b9c87b2",
		PegBridgeAddr:        "0x6239c3644abd336fad322a24dd2930a5aa3fa844a5d239e3b02584e79c791053",
		MsgPackage:           "cosmwasm.wasm.v1",
		KeyringBackend:       "file",
		TransactorPassphrase: "12341234",
		GasAdjustment:        1.3,
		GasPrices:            "0.01usei",
		Timeout:              "15s",
		HomeDir:              "../home_config/",
	}

	cc := client.NewCosClient(cfg)
	if cc == nil {
		log.Fatalln("fail to init cos client")
	}

	paused, err := cc.IsPaused("0x78167721f3f0bd7c20c4c783db10b95cc1207d5b980c02fc252b4825b9c87b2")
	if err != nil {
		log.Fatalln(err)
	}
	log.Infof("pause status: %v", paused)

	if !paused {
		txHash, err := cc.Pause("0x78167721f3f0bd7c20c4c783db10b95cc1207d5b980c02fc252b4825b9c87b2")
		if err != nil {
			log.Fatalln(err)
		}
		log.Infof("pause txHash: %x", txHash)
	}

	paused, err = cc.IsPaused("0x78167721f3f0bd7c20c4c783db10b95cc1207d5b980c02fc252b4825b9c87b2")
	if err != nil {
		log.Fatalln(err)
	}
	log.Infof("pause status: %v", paused)

	txHash, err := cc.Unpause("0x78167721f3f0bd7c20c4c783db10b95cc1207d5b980c02fc252b4825b9c87b2")
	if err != nil {
		log.Fatalln(err)
	}
	log.Infof("unpause txHash: %x", txHash)

	paused, err = cc.IsPaused("0x78167721f3f0bd7c20c4c783db10b95cc1207d5b980c02fc252b4825b9c87b2")
	if err != nil {
		log.Fatalln(err)
	}
	log.Infof("pause status: %v", paused)
}
