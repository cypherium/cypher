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

// Package reconfig implements Cypherium reconfiguration.
package reconfig

import (
	"fmt"
	"sync"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus/ethash"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/trie"
)

type txService struct {
	s               serviceI
	cph             *ReconfigBackend
	txPool          *core.TxPool
	bc              *core.BlockChain
	kbc             *core.KeyBlockChain
	config          *params.ChainConfig
	pendingLogsFeed *event.Feed
	mu              sync.Mutex
	mux             *event.TypeMux
	proposedChain   *proposedChain
	chainEventChan  chan core.ChainEvent
	chainEventSub   event.Subscription
}

func newTxService(s serviceI, backend *ReconfigBackend, config *params.ChainConfig) *txService {
	txS := &txService{
		s:      s,
		cph:    backend,
		bc:     backend.BlockChain(),
		kbc:    backend.KeyBlockChain(),
		txPool: backend.TxPool(),
		//		chainEventChan: make(chan core.ChainEvent, 1),
		config:        config,
		proposedChain: newProposedChain(),
		mux:           backend.EventMux(),
	}

	//	txS.chainEventSub = backend.BlockChain().SubscribeChainEvent(txS.chainEventChan)
	txS.proposedChain.clear(txS.bc.CurrentBlock())

	txS.bc.ProcInsertDone = txS.procBlockDone

	//go txS.eventLoop()

	return txS
}

func (txS *txService) tryProposalNewKeyBlock(keyblock *types.KeyBlock) ([]byte, error) {
	txS.mu.Lock()
	defer txS.mu.Unlock()

	work := txS.createWork()

	header := work.header
	// commit state root after all state transitions.
	ethash.AccumulateRewards(txS.bc.Config(), work.publicState, header, nil)
	header.Root = work.publicState.IntermediateRoot(false)

	header.BlockType = types.Key_Block
	header.Difficulty = keyblock.Difficulty()
	header.MixDigest = keyblock.MixDigest()
	header.Nonce = types.EncodeNonce(keyblock.Nonce())
	header.KeyHash = keyblock.ParentHash()

	block := types.NewBlock(header, nil, nil, nil, new(trie.Trie))
	block.SetKeyblock(keyblock)

	log.Info("Generated next keyblock", "block num", block.Number())

	return block.EncodeToBytes(), nil
}

// Try proposal new txBlock for current txs
func (txS *txService) tryProposalNewBlock(blockType uint8) ([]byte, error) {
	txS.mu.Lock()
	defer txS.mu.Unlock()

	work := txS.createWork()
	transactions := txS.getTransactions()

	committedTxes, publicReceipts, logs := work.commitTransactions(transactions, txS.bc)
	txCount := len(committedTxes)

	if txCount == 0 {
		log.Info("Not minting a new block since there are no pending transactions")
		return nil, fmt.Errorf("Not minting a new block since there are no pending transactions")
	}

	//txS.firePendingBlockEvents(logs)

	header := work.header

	// commit state root after all state transitions.
	ethash.AccumulateRewards(txS.bc.Config(), work.publicState, header, nil)
	header.Root = work.publicState.IntermediateRoot(false)
	header.KeyHash = txS.kbc.CurrentBlock().Hash()

	// update block hash since it is now available, but was not when the
	// receipt/log of individual transactions were created:
	headerHash := header.Hash()
	for _, l := range logs {
		l.BlockHash = headerHash
	}

	block := types.NewBlock(header, committedTxes, nil, publicReceipts, new(trie.Trie))

	log.Info("Generated next block", "block num", block.Number(), "num txes", txCount)

	if err := txS.bc.CommitBlockWithState(false, work.publicState); err != nil {
		panic(err)
	}

	txS.proposedChain.extend(block)

	elapsed := time.Since(time.Unix(0, int64(header.Time)))
	log.Info("🔨  Mined block", "number", block.Number(), "hash", fmt.Sprintf("%x", block.Hash().Bytes()[:4]), "elapsed", elapsed)
	return block.EncodeToBytes(), nil
}

// Verify txBlock
func (txS *txService) verifyTxBlock(txblock *types.Block) error {
	var retErr error
	bc := txS.bc
	kbc := txS.kbc
	blockNum := txblock.NumberU64()
	header := txblock.Header()
	log.Info("verifyTxBlock", "txblock num", blockNum)

	if blockNum <= bc.CurrentBlockN() {
		retErr = fmt.Errorf("invalid header, number:%d, current block number:%d", blockNum, bc.CurrentBlockN())
		return retErr
	}
	if header.KeyHash != kbc.CurrentBlock().Hash() {
		retErr = fmt.Errorf("keyhash:%x does not match current keyhash: %x", header.KeyHash, kbc.CurrentBlock().Hash())
		return retErr
	}
	if bftview.IamLeader(txS.s.GetCurrentView().LeaderIndex) {
		return nil
	}
	err := bc.Engine().VerifyHeader(bc, header, false)
	if err != nil {
		retErr = fmt.Errorf("invalid header, error:%s", err.Error())
		return retErr
	}
	err = bc.Validator().ValidateBody(txblock)
	if err == types.ErrFutureBlock || err == types.ErrUnknownAncestor || err == types.ErrPrunedAncestor {
		retErr = fmt.Errorf("invalid body, error:%s", err.Error())
		return retErr
	}
	/*
		statedb, _, err := bc.State()
		if err != nil {
			retErr = fmt.Errorf("cannot get statedb, error:%s", err.Error())
			return retErr
		}
		receipts, _, usedGas, err := bc.Processor.Process(txblock, statedb, vm.Config{})
		if err != nil {
			retErr = fmt.Errorf("cannot get receipts, error:%s", err.Error())
			return retErr
		}
		err = bc.Validator.ValidateState(txblock, bc.GetBlockByHash(txblock.ParentHash()), statedb, receipts, usedGas)
		if err != nil {
			retErr = fmt.Errorf("Invalid state, error:%s", err.Error())
			return retErr
		}
	*/
	return nil
}

// New txBlock done, when consensus agreement completed
func (txS *txService) decideNewBlock(block *types.Block, sig []byte, mask []byte) error {
	log.Info("decideNewBlock", "TxBlock Number", block.NumberU64(), "txs", len(block.Transactions()))
	bc := txS.bc
	if bc.HasBlockAndState(block.Hash(), block.NumberU64()) {
		return nil
	}
	block.SetSignature(sig, mask)
	//	log.Info("decideNewBlock", "extra", block.Extra())
	_, err := bc.InsertBlock(block)
	if err != nil {
		log.Error("decideNewBlock.InsertChain", "error", err)
		return err
	}
	txS.mux.Post(core.NewMinedBlockEvent{Block: block})
	log.Info("decideNewBlock InsertBlock ok")
	return nil
}

//-----------------------------------------------------------------------------------------------------
func (txS *txService) procBlockDone(newBlock *types.Block) {
	log.Info("chainBlockEvent...", "number", newBlock.NumberU64())
	txS.txPool.RemoveBatch(newBlock.Transactions())

	if txS.s.isRunning() {
		txS.updateChainPerNewHead(newBlock)
	} else {
		txS.proposedChain.setHead(newBlock)
	}

	txS.s.procBlockDone(newBlock)

}
func (txS *txService) eventLoop() {
	defer txS.chainEventSub.Unsubscribe()

	for {
		select {
		case ev := <-txS.chainEventChan:
			newBlock := ev.Block
			log.Info("chainBlockEvent...", "number", newBlock.NumberU64())

			if txS.s.isRunning() {
				txS.updateChainPerNewHead(newBlock)
			} else {
				txS.proposedChain.setHead(newBlock)
			}

			txS.s.procBlockDone(newBlock)
			//if newBlock.BlockType() == types.Key_Block {
			//	txS.txPool.ResetHead(newBlock.Header())
			//}
			//txS.txPool.RemoveBatch(newBlock.Transactions())

		// system stopped
		case <-txS.chainEventSub.Err():
			return
		}
	}
}

type AddressTxes map[common.Address]types.Transactions

func (txS *txService) updateChainPerNewHead(newBlock *types.Block) {
	txS.mu.Lock()
	defer txS.mu.Unlock()

	txS.proposedChain.accept(newBlock)
}

// Assumes mu is held.
func (txS *txService) createWork() *work {
	parent := txS.bc.CurrentBlock()
	parentNumber := parent.Number()

	parentTime := int64(parent.Time())
	tstamp := time.Now().UnixNano() / 1e6

	if parentTime >= tstamp { // Each successive block needs to be after its predecessor.
		tstamp = parentTime + 1
	}
	log.Info("createWork", "parent.Difficulty()", parent.Difficulty())
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     parentNumber.Add(parentNumber, common.Big1),
		Difficulty: parent.Difficulty(), //ethash.CalcDifficulty(txS.config, uint64(tstamp), parent.Header()),
		GasLimit:   txS.cph.calcGasLimitFunc(parent),
		GasUsed:    0,
		Coinbase:   bftview.GetServerCoinBase(),
		Time:       uint64(tstamp),
	}
	log.Info("createWork", "GasLimit", header.GasLimit)
	publicState, err := txS.bc.StateAt(parent.Root())
	if err != nil {
		panic(fmt.Sprint("failed to get parent state: ", err))
	}

	return &work{
		config:      txS.config,
		publicState: publicState,
		header:      header,
		txPool:      txS.txPool,
	}
}

func (txS *txService) getTransactions() *types.TransactionsByPriceAndNonce {
	allAddrTxes, err := txS.txPool.Pending()
	if err != nil { // TODO: handle
		panic(err)
	}
	addrTxes := txS.proposedChain.withoutProposedTxes(allAddrTxes)
	return types.NewTransactionsByPriceAndNonce(txS.config, txS.bc.CurrentBlock().Number(), addrTxes)
}

// Sends-off events asynchronously.
func (txS *txService) firePendingBlockEvents(logs []*types.Log) {
	// Copy logs before we mutate them, adding a block hash.
	copiedLogs := make([]*types.Log, len(logs))
	for i, l := range logs {
		copiedLogs[i] = new(types.Log)
		*copiedLogs[i] = *l
	}

	go func() {
		txS.cph.pendingLogsFeed.Send(copiedLogs)
		txS.cph.eventMux.Post(core.PendingStateEvent{})
	}()
}

// Current state information for building the next block
type work struct {
	config      *params.ChainConfig
	publicState *state.StateDB
	Block       *types.Block
	header      *types.Header
	txPool      *core.TxPool
}

func (env *work) commitTransactions(txes *types.TransactionsByPriceAndNonce, bc *core.BlockChain) (types.Transactions, types.Receipts, []*types.Log) {
	var allLogs []*types.Log
	var committedTxes types.Transactions
	var publicReceipts types.Receipts
	//	var failedTxes types.Transactions

	gp := new(core.GasPool).AddGas(env.header.GasLimit)
	txCount := 0

	for {
		tx := txes.Peek()
		if tx == nil {
			break
		}
		if to := tx.To(); to != nil {
			for _, banned := range params.BlackAddressList {
				if *to == banned {
					log.Warn("Discarding transaction to banned address",
						"hash", tx.Hash(),
						"to", banned.Hex())
					txes.Pop()
					continue
				}
			}
		}
		env.publicState.Prepare(tx.Hash(), common.Hash{}, txCount)

		publicReceipt, err := env.commitTransaction(tx, bc, gp)
		switch {
		case err != nil:
			log.Info("TX failed, will be removed", "hash", tx.Hash(), "err", err)
			//failedTxes = append(failedTxes, tx)

			txes.Pop() // skip rest of txes from this account
		default:
			txCount++
			committedTxes = append(committedTxes, tx)

			publicReceipts = append(publicReceipts, publicReceipt)
			allLogs = append(allLogs, publicReceipt.Logs...)

			txes.Shift()
		}
	}
	//	env.txPool.RemoveBatch(failedTxes)
	return committedTxes, publicReceipts, allLogs
}

func (env *work) commitTransaction(tx *types.Transaction, bc *core.BlockChain, gp *core.GasPool) (*types.Receipt, error) {
	publicSnapshot := env.publicState.Snapshot()

	var author *common.Address
	var vmConf vm.Config
	publicReceipt, err := core.ApplyTransaction(env.config, bc, author, gp, env.publicState, env.header, tx, &env.header.GasUsed, vmConf)
	if err != nil {
		env.publicState.RevertToSnapshot(publicSnapshot)
		return nil, err
	}
	//txnStart := time.Now()
	//log.EmitCheckpoint(log.TxCompleted, "tx", tx.Hash().Hex(), "time", time.Since(txnStart))

	return publicReceipt, nil
}
