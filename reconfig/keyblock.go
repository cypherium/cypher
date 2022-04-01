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
	"math"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
)

type keyService struct {
	s               serviceI
	muBestCandidate sync.Mutex
	bestCandidate   *types.Candidate
	candidatepool   *core.CandidatePool
	bc              *core.BlockChain
	kbc             *core.KeyBlockChain
	engine          consensus.Engine
	config          *params.ChainConfig
}

func newKeyService(s serviceI, backend *ReconfigBackend, config *params.ChainConfig) *keyService {
	keyS := new(keyService)
	keyS.s = s
	keyS.candidatepool = backend.CandidatePool()
	keyS.bc = backend.BlockChain()
	keyS.kbc = backend.KeyBlockChain()
	keyS.engine = backend.Engine()
	keyS.config = config
	return keyS
}

// Verify keyblock
func (keyS *keyService) verifyKeyBlock(keyblock *types.KeyBlock, bestCandi *types.Candidate) error { //
	log.Info("@verifyKeyBlock", "number", keyblock.NumberU64())
	kbc := keyS.kbc
	if keyblock.LeaderPubKey() == bftview.GetServerInfo(bftview.PublicKey) {
		curKeyblock := kbc.CurrentBlock()
		if keyblock.NumberU64() != curKeyblock.NumberU64()+1 {
			return fmt.Errorf("verifyKeyBlock,number is not %d", curKeyblock.NumberU64()+1)
		}
		if keyblock.ParentHash() != curKeyblock.Hash() {
			//log.Error("verifyKeyBlock", "Non contiguous consensus prevhash", keyblock.ParentHash(), "currenthash", curKeyblock.Hash())
			return fmt.Errorf("verifyKeyBlock,Non contiguous key block's hash")
		}
		return nil
	}

	var newNode *common.Cnode
	if keyblock.HasNewNode() {
		newNode = &common.Cnode{
			Address:  net.IP(bestCandi.IP).String() + ":" + strconv.Itoa(bestCandi.Port),
			CoinBase: keyblock.InAddress(),
			Public:   keyblock.InPubKey(),
		}
	}

	if kbc.HasBlock(keyblock.Hash(), keyblock.NumberU64()) { //First come from p2p
		log.Info("verifyKeyBlock exist!", "number", keyblock.NumberU64())
		mb := bftview.LoadMember(keyblock.NumberU64(), keyblock.Hash(), true)
		if mb == nil {
			mb, _ = bftview.GetCommittee(newNode, keyblock, true)
			if mb != nil {
				mb.Store(keyblock)
			}
		}

		if mb != nil {
			keyS.s.syncCommittee(mb, keyblock)
		}

		return nil
	}
	curKeyblock := keyS.kbc.CurrentBlock()
	if keyblock.NumberU64() != curKeyblock.NumberU64()+1 {
		return fmt.Errorf("verifyKeyBlock,number is not %d", curKeyblock.NumberU64()+1)
	}
	if keyblock.ParentHash() != curKeyblock.Hash() {
		//log.Error("verifyKeyBlock", "Non contiguous consensus prevhash", keyblock.ParentHash(), "currenthash", curKeyblock.Hash())
		return fmt.Errorf("verifyKeyBlock,Non contiguous key block's hash")
	}
	if keyblock.T_Number() != keyS.bc.CurrentBlockN() {
		return fmt.Errorf("verifyKeyBlock, T_Number is not current, cur tx number:%d, k_t_number:%d", keyS.bc.CurrentBlockN(), keyblock.T_Number())
	}
	viewleaderIndex := keyS.s.GetCurrentView().LeaderIndex
	index := bftview.GetMemberIndex(keyblock.LeaderPubKey())
	if index != int(viewleaderIndex) {
		return fmt.Errorf("verifyKeyBlock,leaderindex(%d) error, nowIndex:%d", viewleaderIndex, index)
	}
	if keyblock.InAddress() == "" || keyblock.InPubKey() == "" || keyblock.LeaderPubKey() == "" || keyblock.LeaderAddress() == "" {
		return fmt.Errorf("verifyKeyBlock,in or leader public key is empty")
	}

	if !keyblock.TypeCheck(kbc.CurrentBlock().T_Number()) {
		return fmt.Errorf("verifyKeyBlock, check failed, current keynumber:%d,keyblock T_Number:%d", kbc.CurrentBlockN(), keyblock.T_Number())
	}

	keyType := keyblock.BlockType()
	if keyType == types.PowReconfig || keyType == types.PacePowReconfig {
		if bestCandi == nil {
			return fmt.Errorf("keyblock verify failed, pow reconfig need the best candidate")
		}
		bestCandi.KeyCandidate.BlockType = keyType
		//log.Info("keyblock verify", "keyblock.Header", keyblock.Header(), "bestCandi.Header", bestCandi.KeyCandidate)
		if keyblock.Header().HashWithCandi() != bestCandi.KeyCandidate.HashWithCandi() {
			return fmt.Errorf("keyblock verify failed,best candidate's hash is not equal me")
		}
		if keyblock.InPubKey() != bestCandi.PubKey || keyblock.InAddress() != bestCandi.Coinbase {
			return fmt.Errorf("keyblock verify failed, best candidate in info is not correct")
		}

		best := keyS.getBestCandidate(false)
		if best != nil && best.KeyCandidate.Nonce.Uint64() < bestCandi.KeyCandidate.Nonce.Uint64() { //compare best with local
			return fmt.Errorf("keyblock verify failed, not the best, my nonce is less than leader")
		}
		//verify bestCandi's MixDigest,Nonce with ip
		err := keyS.engine.VerifyCandidate(keyS.kbc, bestCandi)
		if err != nil {
			return err //fmt.Errorf("keyblock verify failed,candidate pow verification failed!")
		}
	} else if keyType == types.TimeReconfig {
		//
	} else if keyType == types.PaceReconfig {
		//
	} else {
		return fmt.Errorf("verifyKeyBlock,error BlockType:%d", keyblock.BlockType())
	}

	mb, outer := bftview.GetCommittee(newNode, keyblock, true)
	if mb == nil {
		return fmt.Errorf("keyblock verify failed, can't get new committee")
	}
	if keyblock.CommitteeHash() != mb.RlpHash() {
		return fmt.Errorf("keyblock verify failed, chash:%x, block hash:%x", mb.RlpHash(), keyblock.CommitteeHash())
	}

	if keyType == types.PowReconfig || keyType == types.PacePowReconfig {
		if outer == nil {
			return fmt.Errorf("keyblock verify failed, PowReconfig or PacePowReconfig should has outer")
		}
		outAddress := keyblock.OutAddress(0)
		isBadAddress := false
		if outAddress[0] == '*' {
			outAddress = outAddress[1:]
			isBadAddress = true
		}
		if outer.CoinBase != outAddress || outer.Public != keyblock.OutPubKey() {
			return fmt.Errorf("keyblock verify failed, outer is not correct,outer=%s,my outer=%s", outAddress, outer.CoinBase)
		}
		if isBadAddress {
			badAddress := keyS.getBadAddress()
			if outAddress != badAddress {
				return fmt.Errorf("keyblock verify failed, outer is not correct,outer =%s, badAddress=%s", outAddress, badAddress)
			}
		}
	}

	if mb.Leader().CoinBase != keyblock.LeaderAddress() || mb.Leader().Public != keyblock.LeaderPubKey() {
		return fmt.Errorf("keyblock verify failed, leader is not correct")
	}
	if mb.In().CoinBase != keyblock.InAddress() || mb.In().Public != keyblock.InPubKey() {
		return fmt.Errorf("keyblock verify failed, in is not correct")
	}

	if bftview.LoadMember(keyblock.NumberU64(), keyblock.Hash(), true) == nil {
		mb.Store(keyblock)
	}
	keyS.s.syncCommittee(mb, keyblock)

	return nil
}

// Try to change committee and proposal a new keyblock
func (keyS *keyService) tryProposalChangeCommittee(leaderIndex uint, isDone bool) (*types.KeyBlock, *bftview.Committee, *types.Candidate, error) {
	log.Info("tryProposalChangeCommittee", "tx number", keyS.bc.CurrentBlockN(), "isDone", isDone, "leaderIndex", leaderIndex)
	curKeyBlock := keyS.kbc.CurrentBlock()
	curKNumber := curKeyBlock.Number()
	curKHash := curKeyBlock.Hash()
	mb := bftview.GetCurrentMember()
	if mb == nil {
		return nil, nil, nil, fmt.Errorf("not found committee in keyblock number=%d", curKNumber)
	}
	mb = mb.Copy()
	header := &types.KeyBlockHeader{
		Number:     curKNumber.Add(curKNumber, common.Big1),
		ParentHash: curKHash,
		Difficulty: curKeyBlock.Difficulty(),
		Time:       uint64(time.Now().Unix()),
	}

	var outerPublic, outerCoinBase string
	best := keyS.getBestCandidate(false)

	var reconfigType uint8
	if isDone {
		if best != nil {
			reconfigType = types.PowReconfig
		} else {
			reconfigType = types.TimeReconfig
		}
	} else {
		if best != nil {
			reconfigType = types.PacePowReconfig
		} else {
			reconfigType = types.PaceReconfig
		}
	}
	header.BlockType = reconfigType

	if reconfigType == types.PowReconfig || reconfigType == types.PacePowReconfig {
		ck := best.KeyCandidate
		header.Time, header.Difficulty, header.MixDigest, header.Nonce = ck.Time, ck.Difficulty, ck.MixDigest, ck.Nonce
		newNode := &common.Cnode{
			Address:  net.IP(best.IP).String() + ":" + strconv.Itoa(best.Port),
			CoinBase: best.Coinbase,
			Public:   best.PubKey,
		}

		badAddress := keyS.getBadAddress()
		outer := mb.Add(newNode, int(leaderIndex), badAddress)
		if outer == nil { //not new add
			return nil, nil, nil, fmt.Errorf("not new best candidate")
		}
		outerPublic, outerCoinBase = outer.Public, outer.CoinBase
		if badAddress != "" && outerCoinBase == badAddress {
			outerCoinBase = "*" + outerCoinBase
		}

	} else { //exchange in internal
		mb.Add(nil, int(leaderIndex), "")
		outerPublic, outerCoinBase = "", ""
	}

	header.CommitteeHash = mb.RlpHash()
	header.T_Number = keyS.bc.CurrentBlockN()
	keyblock := types.NewKeyBlock(header)
	keyblock = keyblock.WithBody(mb.In().Public, mb.In().CoinBase, outerPublic, outerCoinBase, mb.Leader().Public, mb.Leader().CoinBase)
	log.Info("tryProposalChangeCommittee", "committeeHash", header.CommitteeHash, "leader", keyblock.LeaderPubKey(), "outerCoinBase", outerCoinBase)
	mb.Store(keyblock)
	return keyblock, mb, best, nil
}

func (keyS *keyService) getNextLeaderIndex(leaderIndex uint) uint {
	mb := bftview.GetCurrentMember()
	if mb == nil {
		return 1
	}

	committeeSize := len(mb.List)
	leaderIndex++
	if leaderIndex >= uint(committeeSize) {
		leaderIndex = 0
	}
	kbc := keyS.kbc
	curblock := kbc.CurrentBlock()
	curNumber := curblock.NumberU64()
	if curNumber == 0 {
		return leaderIndex
	}

	badNodes := make(map[string]bool)
	badAddr := keyS.getBadAddress()
	if badAddr != "" {
		badNodes[badAddr] = true
	}

	for loopi := 0; loopi < 3; loopi++ {
		if curblock.BlockType() == types.PaceReconfig || curblock.BlockType() == types.PacePowReconfig {
			curblock := kbc.GetBlockByHash(curblock.ParentHash())
			if curblock != nil {
				badNodes[curblock.LeaderAddress()] = true
			}
		}
	}

	if len(badNodes) > 0 {
		curNodes := kbc.GetCommitteeByNumber(curNumber)
		for i, r := range curNodes {
			if leaderIndex == uint(i) {
				if badNodes[r.CoinBase] {
					leaderIndex = uint(i) + 1
					if leaderIndex == uint(committeeSize) {
						leaderIndex = 0
					}

				}
			}
		}
	}
	return leaderIndex
}

func (keyS *keyService) getBadAddress() string {
	mb := bftview.GetCurrentMember()
	if mb == nil {
		return ""
	}
	cmLen := len(mb.List)
	exps := make(map[int]int)

	fromN := keyS.kbc.CurrentBlock().T_Number() + 1
	ToN := keyS.bc.CurrentBlockN()
	if fromN > ToN {
		return ""
	}

	for i := fromN; i <= ToN; i++ {
		block := keyS.bc.GetBlockByNumber(uint64(i))
		if block == nil {
			return ""
		}
		si := block.SignInfo()
		indexs := hotstuff.MaskToExceptionIndexs(si.Exceptions, cmLen)
		if len(indexs) > 0 {
			for j := 0; j < len(indexs); j++ {
				exps[indexs[j]]++
			}
		}
	}

	genesisCm := keyS.config.GenCommittee
	isGenesis := func(addr string) bool {
		for _, r := range genesisCm {
			if r.CoinBase == addr {
				return true
			}
		}
		return false
	}

	ii := 0
	maxV := 0
	for i := 0; i < cmLen; i++ {
		v, ok := exps[i]
		if !ok {
			continue
		}

		if ToN-fromN < 10 && isGenesis(mb.List[i].CoinBase) {
			v = v - 1
		}

		if v > maxV {
			maxV = v
			ii = i
		}
	}
	return mb.List[ii].CoinBase
}

// Clear candidate in cache
func (keyS *keyService) clearCandidate(keyblock *types.KeyBlock) {
	keyS.muBestCandidate.Lock()
	defer keyS.muBestCandidate.Unlock()
	keyS.candidatepool.ClearObsolete(keyblock.Number())
	keyS.bestCandidate = nil
}

// Get the best candidate by lowest nonce
func (keyS *keyService) getBestCandidate(refresh bool) *types.Candidate {
	keyS.muBestCandidate.Lock()
	defer keyS.muBestCandidate.Unlock()

	if refresh {
		kNumber := keyS.kbc.CurrentBlockN() + 1
		if keyS.bestCandidate != nil && keyS.bestCandidate.KeyCandidate.Number.Uint64() != kNumber {
			keyS.bestCandidate = nil
		}
		contents := keyS.candidatepool.Content()
		if len(contents) > 0 {
			best := contents[0]
			if best.KeyCandidate.Number.Uint64() == kNumber {
				if keyS.bestCandidate == nil {
					keyS.bestCandidate = best
				} else if best.KeyCandidate.Nonce.Uint64() < keyS.bestCandidate.KeyCandidate.Nonce.Uint64() {
					keyS.bestCandidate = best
				}
			} else {
				log.Warn("getBestCandidate", "have not get the candidate keyNumber", keyS.kbc.CurrentBlockN(), "KeyCandidate number", best.KeyCandidate.Number.Uint64())
			}
		}
	} //end if refresh
	if keyS.bestCandidate != nil {
		if bftview.GetMemberIndex(keyS.bestCandidate.PubKey) >= 0 {
			return nil
		}
	}
	return keyS.bestCandidate
}

// Set the best candidate by pow
func (keyS *keyService) setBestCandidate(bestCandidates []*types.Candidate) {
	bestNonce := uint64(math.MaxUint64)
	best := keyS.getBestCandidate(true)
	if best != nil {
		bestNonce = best.KeyCandidate.Nonce.Uint64()
	}
	keyNumber := keyS.kbc.CurrentBlockN() + 1
	for _, cand := range bestCandidates {
		ck := cand.KeyCandidate
		if ck.Number.Uint64() == keyNumber && ck.Nonce.Uint64() < bestNonce && bftview.GetMemberIndex(cand.PubKey) < 0 {
			bestNonce = ck.Nonce.Uint64()
			keyS.muBestCandidate.Lock()
			keyS.bestCandidate = cand
			keyS.muBestCandidate.Unlock()
		}
	}
}
