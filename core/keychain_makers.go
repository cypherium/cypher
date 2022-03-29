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
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/params"
	"golang.org/x/crypto/ed25519"
)

// KeyBlockGen creates blocks for testing.
// See GenerateKeyChain for a detailed explanation.
type KeyBlockGen struct {
	i              int
	parent         *types.KeyBlock
	chain          []*types.KeyBlock
	keyChainReader types.KeyChainReader
	header         *types.KeyBlockHeader

	config       *params.ChainConfig
	engine       consensus.Engine
	leaderPubKey ed25519.PublicKey
}

// SetLeader sets the leader of the generated block.
// It can be called at most once.
func (b *KeyBlockGen) SetLeader(pubKey ed25519.PublicKey) {
	copy(b.leaderPubKey, pubKey)
}

// Number returns the block number of the block being generated.
func (b *KeyBlockGen) Number() *big.Int {
	return new(big.Int).Set(b.header.Number)
}

// PrevBlock returns a previously generated block by number. It panics if
// num is greater or equal to the number of the block being generated.
// For index -1, PrevBlock returns the parent block given to GenerateChain.
func (b *KeyBlockGen) PrevBlock(index int) *types.KeyBlock {
	if index >= b.i {
		panic("block index out of range")
	}
	if index == -1 {
		return b.parent
	}
	return b.chain[index]
}

// OffsetTime modifies the time instance of a block, implicitly changing its
// associated difficulty. It's useful to test scenarios where forking is not
// tied to chain length directly.
func (b *KeyBlockGen) OffsetTime(seconds int64) {
	b.header.Time = b.header.Time + uint64(seconds)
	if b.header.Time < b.parent.Header().Time {
		panic("block time out of range")
	}
	b.header.Difficulty = b.engine.CalcKeyBlockDifficulty(b.keyChainReader, b.header.Time, b.parent.Header())
}

// GenerateKeyChain creates a chain of n key blocks. The first block's
// parent will be the provided parent.
//
// The generator function is called with a new block generator for
// every block.
//
// Blocks created by GenerateKeyChain do not contain valid proof of work
// values. Inserting them into KeyBlockChain requires use of FakePow or
// a similar non-validating proof of work implementation.
func GenerateKeyChain(config *params.ChainConfig, parent *types.KeyBlock, engine consensus.Engine, db ethdb.Database, n int, gen func(int, *KeyBlockGen)) []*types.KeyBlock {
	if config == nil {
		config = params.TestChainConfig
	}
	blocks := make(types.KeyBlocks, n)
	genKeyBlock := func(i int, parent *types.KeyBlock) *types.KeyBlock {
		blockchain, _ := NewKeyBlockChain(nil, db, nil, config, engine, nil)
		defer blockchain.Stop()

		b := &KeyBlockGen{i: i, parent: parent, chain: blocks, keyChainReader: blockchain, config: config, engine: engine}
		b.header = makeKeyHeader(b.keyChainReader, parent, b.engine)
		// Execute any user modifications to the block and finalize it
		if gen != nil {
			gen(i, b)
		}

		if b.engine != nil {
			block, _ := blockchain.FinalizeKeyBlock(b.header)
			return block.CopyMe()
			//return block
		}
		return nil
	}
	for i := 0; i < n; i++ {
		block := genKeyBlock(i, parent)
		blocks[i] = block
		parent = block
	}

	return blocks
}

func makeKeyHeader(chain types.KeyChainReader, parent *types.KeyBlock, engine consensus.Engine) *types.KeyBlockHeader {
	var time uint64
	if parent.Time() == 0 {
		time = 10
	} else {
		time = parent.Time() + 10 // block time is fixed at 10 seconds
	}

	return &types.KeyBlockHeader{
		ParentHash: parent.Hash(),
		Difficulty: engine.CalcKeyBlockDifficulty(chain, time, &types.KeyBlockHeader{
			Number:     parent.Number(),
			Time:       time - 10,
			Difficulty: parent.Difficulty(),
		}),
		Number: new(big.Int).Add(parent.Number(), common.Big1),
		Time:   time,
	}
}

// makeHeaderChain creates a deterministic chain of headers rooted at parent.
func makeKeyHeaderChain(parent *types.KeyBlockHeader, n int, engine consensus.Engine, db ethdb.Database, seed int) []*types.KeyBlockHeader {
	blocks := makeKeyBlockChain(types.NewKeyBlockWithHeader(parent), n, engine, db, seed)
	headers := make([]*types.KeyBlockHeader, len(blocks))
	for i, block := range blocks {
		headers[i] = block.Header()
	}
	return headers
}

// makeBlockChain creates a deterministic chain of blocks rooted at parent.
func makeKeyBlockChain(parent *types.KeyBlock, n int, engine consensus.Engine, db ethdb.Database, seed int) []*types.KeyBlock {
	blocks := GenerateKeyChain(params.TestChainConfig, parent, engine, db, n, func(i int, b *KeyBlockGen) {

	})
	return blocks
}
