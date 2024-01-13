// Copyright 2015 The go-ethereum Authors
// Copyright 2017 The cypherBFT Authors
// This file is part of the cypherBFT library.
//
// The cypherBFT library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The cypherBFT library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the cypherBFT library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/common/math"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/log"

	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
)

//go:generate gencodec -type GenesisKey -field-override keyGenesisSpecMarshaling -out gen_key_genesis.go
//go:generate gencodec -type GenesisKeyAccount -field-override keyGenesisAccountMarshaling -out gen_key_genesis_account.go

var errKeyGenesisNoConfig = errors.New("key genesis has no key chain configuration")

// GenesisKey specifies the header fields, state of a genesis block. It also defines hard
// fork switch-over blocks through the chain configuration.
type GenesisKey struct {
	Config     *params.ChainConfig `json:"config"`
	Version    string              `json:"version"`
	ParentHash common.Hash         `json:"parentHash"`
	Nonce      uint64              `json:"nonce"`
	Time       uint64              `json:"timestamp"`
	ExtraData  string              `json:"extraData"`
	Number     uint64              `json:"number"`
	Difficulty *big.Int            `json:"difficulty" 			gencodec:"required"`
	MixHash    common.Hash         `json:"mixHash"`
	Alloc      KeyGenesisAlloc     `json:"alloc"      			gencodec:"required"`

	Signature     []byte `json:"signatrue"`
	Exceptions    []byte `json:"exceptions"`
	LeaderPubKey  string `json:"leaderPubKey"`
	LeaderAddress string
	InPubKey      string `json:"inPubKey"            	gencodec:"required"`
	OutPubKey     string `json:"outPubKey"            	gencodec:"required"`
	InAddress     string `json:"inAddress"            	gencodec:"required"`
	OutAddress    string `json:"outAddress"            	gencodec:"required"`
}

// KeyGenesisAlloc specifies the initial state that is part of the genesis block.
type KeyGenesisAlloc map[common.Address]GenesisKeyAccount

func (ga *KeyGenesisAlloc) UnmarshalJSON(data []byte) error {
	m := make(map[common.UnprefixedAddress]GenesisKeyAccount)
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	*ga = make(KeyGenesisAlloc)
	for addr, a := range m {
		(*ga)[common.Address(addr)] = a
	}
	return nil
}

// GenesisKeyAccount is an account in the state of the genesis block.
type GenesisKeyAccount struct {
	Code    []byte                      `json:"code,omitempty"`
	Storage map[common.Hash]common.Hash `json:"storage,omitempty"`
	Balance *big.Int                    `json:"balance" gencodec:"required"`
	Nonce   uint64                      `json:"nonce,omitempty"`
}

// field type overrides for gencodec
type keyGenesisSpecMarshaling struct {
	Version       string
	ParentHash    common.Hash
	Nonce         math.HexOrDecimal64
	Time          math.HexOrDecimal64
	ExtraData     string
	Number        math.HexOrDecimal64
	Difficulty    *math.HexOrDecimal256
	Alloc         map[common.UnprefixedAddress]GenesisKeyAccount
	Signature     hexutil.Bytes
	Exceptions    hexutil.Bytes
	LeaderPubKey  string
	LeaderAddress string
	InPubKey      string
	OutPubKey     string
	InAddress     string
	OutAddress    string
}

type keyGenesisAccountMarshaling struct {
	Code    hexutil.Bytes
	Balance *math.HexOrDecimal256
	Nonce   math.HexOrDecimal64
	Storage map[storageJSON]storageJSON
}

//type storageJSON common.Hash

// KeyGenesisMismatchError is raised when trying to overwrite an existing
// genesis block with an incompatible one.
type KeyGenesisMismatchError struct {
	Stored, New common.Hash
}

func (e *KeyGenesisMismatchError) Error() string {
	return fmt.Sprintf("database already contains an incompatible genesis block (have %x, new %x)", e.Stored[:8], e.New[:8])
}

// SetupGenesisBlock writes or updates the genesis block in db.
// The block that will be used is:
//
//                          genesis == nil       genesis != nil
//                       +------------------------------------------
//     db has no genesis |  main-net default  |  genesis
//     db has genesis    |  from DB           |  genesis (if compatible)
//
// The stored chain configuration will be updated if it is compatible (i.e. does not
// specify a fork block below the local head block). In case of a conflict, the
// error is a *params.ConfigCompatError and the new, unwritten config is returned.
//
// The returned chain configuration is never nil.
func SetupGenesisKeyBlock(db ethdb.Database, genesis *GenesisKey) (*params.ChainConfig, common.Hash, error) {
	if genesis != nil && genesis.Config == nil {
		return params.AllEthashProtocolChanges, common.Hash{}, errKeyGenesisNoConfig
	}
	bftview.SetCommitteeConfig(db, nil, nil)

	// Just commit the new block if there is no stored genesis block.
	stored := rawdb.ReadKeyBlockHash(db, 0)
	if (stored == common.Hash{}) {
		if genesis == nil {
			panic("Writing genesis key block error!")
		} else {
			log.Info("Writing custom genesis key block")
		}
		block, err := genesis.Commit(db)
		return genesis.Config, block.Hash(), err
	}

	// Check whether the genesis block is already written.
	if genesis != nil {
		keyblock := genesis.ToBlock()
		gc := genesis.Config.GenCommittee
		cnodes := make([]*common.Cnode, len(gc))
		for k, _ := range gc {
			node := gc[k]
			cnodes[k] = &node
		}
		c := bftview.Committee{List: cnodes}
		keyblock.SetCommitteeHash(c.RlpHash())
		hash := keyblock.Hash()
		// Compare the given genesis with
		if keyblock.Hash() != stored {
			return genesis.Config, hash, &KeyGenesisMismatchError{stored, hash}
		}
		committee0 := bftview.LoadMember(0, keyblock.Hash(), true)
		if committee0 == nil {
			panic("Can not found Genesis Committee!")
		}
	}

	// Get the existing chain configuration.
	newCfg := genesis.configOrDefault(stored)
	storeCfg := rawdb.ReadChainConfig(db, stored)
	if storeCfg == nil {
		log.Warn("Found genesis block without chain config")
		rawdb.WriteChainConfig(db, stored, newCfg)
		return newCfg, stored, nil
	}
	// Special case: don't change the existing config of a non-mainnet chain if no new
	// config is supplied. These chains would get AllProtocolChanges (and a compat error)
	// if we just continued here.
	if genesis == nil {
		return storeCfg, stored, nil
	}

	// Check config compatibility and write the config. Compatibility errors
	// are returned to the caller unless we're already at block zero.
	height := rawdb.ReadKeyHeaderNumber(db, rawdb.ReadHeadKeyHeaderHash(db))
	if height == nil {
		return newCfg, stored, fmt.Errorf("missing block number for head header hash")
	}
	rawdb.WriteChainConfig(db, stored, newCfg)
	log.Info("SetupGenesisKeyBlock", "stored hash", stored, "newCfg", newCfg)
	return newCfg, stored, nil
}

func (g *GenesisKey) configOrDefault(ghash common.Hash) *params.ChainConfig {
	switch {
	case g != nil:
		return g.Config
		/*
			case ghash == params.MainnetGenesisHash:
				return params.MainnetChainConfig
			case ghash == params.TestnetGenesisHash:
				return params.TestnetChainConfig
		*/
	default:
		return params.AllEthashProtocolChanges
	}
}

// ToBlock creates the genesis block and writes state of a genesis specification
// to the given database (or discards it if nil).
func (g *GenesisKey) ToBlock() *types.KeyBlock {

	head := &types.KeyBlockHeader{
		ParentHash: g.ParentHash,
		Number:     new(big.Int).SetUint64(g.Number),
		Nonce:      types.EncodeNonce(g.Nonce),
		Time:       g.Time,

		Difficulty: g.Difficulty,
		MixDigest:  g.MixHash,
		BlockType:  types.Initialization,
	}

	if g.Difficulty == nil {
		head.Difficulty = params.GenesisDifficulty
	}
	committees := g.Config.GenCommittee
	var keys []int
	for k := range committees {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	inPubs := ""
	inAdds := ""
	for _, k := range keys {
		inPubs += "," + committees[k].Public
		inAdds += "," + committees[k].CoinBase
	}
	return types.NewKeyBlock(head).WithBody(inPubs[1:], inAdds[1:], "", "", "", "")
}

// Commit writes the block and state of a genesis specification to the database.
// The block is committed as the canonical head block.
func (g *GenesisKey) Commit(db ethdb.Database) (*types.KeyBlock, error) {
	config := g.Config
	if config == nil {
		//config = params.AllEthashProtocolChanges
		return nil, fmt.Errorf("can't commit genesis block without config")

	}
	keyblock := g.ToBlock()
	if keyblock.Number().Sign() != 0 {
		return nil, fmt.Errorf("can't commit genesis block with number > 0")
	}
	gc := g.Config.GenCommittee

	cnodes := make([]*common.Cnode, len(gc))
	for k, _ := range gc {
		node := gc[k]
		cnodes[k] = &node
	}
	c := bftview.Committee{List: cnodes}
	keyblock.SetCommitteeHash(c.RlpHash())
	c.Store(keyblock)

	rawdb.WriteTd(db, keyblock.Hash(), keyblock.NumberU64(), g.Difficulty)
	rawdb.WriteKeyBlock(db, keyblock)
	rawdb.WriteKeyBlockHash(db, keyblock.Hash(), keyblock.NumberU64())
	rawdb.WriteHeadKeyBlockHash(db, keyblock.Hash())
	rawdb.WriteHeadKeyHeaderHash(db, keyblock.Hash())

	rawdb.WriteChainConfig(db, keyblock.Hash(), config)
	return keyblock, nil
}

// MustCommit writes the genesis block and state to db, panicking on error.
// The block is committed as the head of key block.
func (g *GenesisKey) MustCommit(db ethdb.Database) *types.KeyBlock {
	block, err := g.Commit(db)
	if err != nil {
		panic(err)
	}
	return block
}
