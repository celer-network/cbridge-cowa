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
		VaultBridgeAddr:      "0xf04a313a7349b120c55c99788f12f712176bb3e5926d012d0ea72fa2bbb85051",
		PegBridgeAddr:        "0x45dbea4617971d93188eda21530bc6503d153313b6f575048c2c35dbc6e4fb06",
		MsgPackage:           "cosmwasm.wasm.v1",
		KeyringBackend:       "file",
		TransactorPassphrase: "12341234",
		GasAdjustment:        1.1,
		GasPrices:            "0.01usei",
		Timeout:              "15s",
		HomeDir:              "../home_config/",
	}

	cc := client.NewCosClient(cfg)
	if cc == nil {
		log.Fatalln("fail to init cos client")
	}
}
