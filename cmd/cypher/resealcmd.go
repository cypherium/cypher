package main

import (
	"encoding/json"
	"os"

	"github.com/cypherium/cypher/cmd/utils"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus/colossusx"
	"github.com/cypherium/cypher/core/rawdb"
	cli "gopkg.in/urfave/cli.v1"
)

var resealKeyGenesisCommand = cli.Command{
	Action:    utils.MigrateFlags(resealKeyGenesis),
	Name:      "reseal-keygenesis",
	Usage:     "Re-seal keyblock #0 with Colossus-X and print nonce/mixHash",
	ArgsUsage: "",
	Flags: []cli.Flag{
		utils.DataDirFlag,
		configFileFlag,
		utils.EthashCacheDirFlag,
		utils.EthashCachesInMemoryFlag,
		utils.EthashCachesOnDiskFlag,
		utils.EthashDatasetDirFlag,
		utils.EthashDatasetsInMemoryFlag,
		utils.EthashDatasetsOnDiskFlag,
	},
	Category: "BLOCKCHAIN COMMANDS",
}

type resealKeyGenesisOut struct {
	OldHash       string `json:"oldHash"`
	NewHash       string `json:"newHash"`
	SealHash      string `json:"sealHash"`
	Nonce         string `json:"nonce"`
	NonceUint64   uint64 `json:"nonceUint64"`
	MixHash       string `json:"mixHash"`
	ParentHash    string `json:"parentHash"`
	Difficulty    string `json:"difficulty"`
	BlockType     uint8  `json:"blockType"`
	CommitteeHash string `json:"committeeHash"`
	TNumber       uint64 `json:"t_Number"`
	Time          uint64 `json:"time"`
}

func resealKeyGenesis(ctx *cli.Context) error {
	stack, cfg := makeConfigNode(ctx)
	defer stack.Close()

	db, err := stack.OpenDatabase("chaindata", 0, 0, "")
	if err != nil {
		utils.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	hash := rawdb.ReadKeyBlockHash(db, 0)
	if hash == (common.Hash{}) {
		utils.Fatalf("No canonical keyblock #0 found. Run init first.")
	}
	block := rawdb.ReadKeyBlock(db, hash, 0)
	if block == nil {
		utils.Fatalf("Failed to load keyblock #0")
	}

	header := block.Header()
	engine := colossusx.New(cfg.Eth.Ethash)

	if err := engine.SealKeyHeaderDeterministic(header, 0); err != nil {
		utils.Fatalf("Failed to reseal keyblock #0: %v", err)
	}

	out := resealKeyGenesisOut{
		OldHash:       block.Hash().Hex(),
		NewHash:       header.Hash().Hex(),
		SealHash:      header.SealHash().Hex(),
		Nonce:         "0x" + common.Bytes2Hex(header.Nonce[:]),
		NonceUint64:   header.Nonce.Uint64(),
		MixHash:       header.MixDigest.Hex(),
		ParentHash:    header.ParentHash.Hex(),
		Difficulty:    header.Difficulty.String(),
		BlockType:     header.BlockType,
		CommitteeHash: header.CommitteeHash.Hex(),
		TNumber:       header.T_Number,
		Time:          header.Time,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
