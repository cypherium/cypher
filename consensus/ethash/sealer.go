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

package ethash

import (
	crand "crypto/rand"
	"math"
	"math/big"
	"math/rand"
	"runtime"
	"sync"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/log"
)

// SealCandidate implements pow.Engine, attempting to find a nonce that satisfies
// the candidate's difficulty requirements.
func (ethash *Ethash) SealCandidate(candidate *types.Candidate, stop <-chan struct{}) (*types.Candidate, error) {
	log.Info("pow work,finding...", "PowMode", ethash.config.PowMode)
	// If we're running a fake PoW, simply return a 0 nonce immediately
	if ethash.config.PowMode == ModeFake || ethash.config.PowMode == ModeFullFake {
		candidate.KeyCandidate.Nonce, candidate.KeyCandidate.MixDigest = types.BlockNonce{}, common.Hash{}
		return candidate, nil
	}
	// Create a runner and the multiple search threads it directs
	abort := make(chan struct{})
	found := make(chan *types.Candidate)

	ethash.lock.Lock()
	threads := ethash.threads
	if ethash.rand == nil {
		seed, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
		if err != nil {
			ethash.lock.Unlock()
			return nil, err
		}
		ethash.rand = rand.New(rand.NewSource(seed.Int64()))
	}

	ethash.lock.Unlock()
	if threads == 0 {
		threads = runtime.NumCPU()
	}
	if threads < 0 {
		threads = 1
	}
	var pend sync.WaitGroup
	for i := 0; i < threads; i++ {
		pend.Add(1)
		go func(id int, nonce uint64) {
			defer pend.Done()
			ethash.mineCandidate(candidate, id, nonce, abort, found)
		}(i, uint64(ethash.rand.Int63()))
	}
	// Wait until sealing is terminated or a nonce is found
	var result *types.Candidate
	select {
	case <-stop:
		// Outside abort, stop all miner threads
		close(abort)
	case result = <-found:

		// One of the threads found a block, abort all others
		close(abort)
	case <-ethash.update:
		// Thread count was changed on user request, restart
		close(abort)
		pend.Wait()
		log.Info("SealCandidate.update")
		return ethash.SealCandidate(candidate, stop)
	}
	// Wait for all miners to terminate and return the block
	pend.Wait()
	return result, nil
}

// mineCandidate is the actual proof-of-work miner that searches for a nonce starting from
// seed that results in correct final block difficulty.
func (ethash *Ethash) mineCandidate(candidate *types.Candidate, id int, seed uint64, abort chan struct{}, found chan *types.Candidate) {
	// Extract some data from the header
	var (
		hash    = candidate.HashNoNonce().Bytes()
		target  = new(big.Int).Div(maxUint256, candidate.KeyCandidate.Difficulty)
		number  = candidate.KeyCandidate.Number.Uint64()
		dataset = ethash.dataset(number)
	)
	// Start generating random nonces until we abort or find a good one
	var (
		attempts = int64(0)
		nonce    = seed
	)
	log.Debug("mineCandidate", "seed", seed)
	logger := log.New("miner", id)
search:
	for {
		select {
		case <-abort:
			// Mining terminated, update stats and abort
			logger.Trace("Ethash nonce search aborted", "attempts", nonce-seed)
			ethash.hashrate.Mark(attempts)
			break search

		default:
			// We don't have to update hash rate on every nonce, so update after after 2^X nonces
			attempts++
			if (attempts % (1 << 15)) == 0 {
				ethash.hashrate.Mark(attempts)
				attempts = 0
			}
			// Compute the PoW value of this nonce
			digest, result := hashimotoFull(dataset.dataset, hash, nonce)

			if new(big.Int).SetBytes(result).Cmp(target) <= 0 {
				foundedTime := time.Now().Unix()
				foundedElapseTime := time.Duration(uint64(foundedTime)-candidate.KeyCandidate.Time) * time.Second
				// Correct nonce found, create a new header with it
				candidate.KeyCandidate.Nonce = types.EncodeNonce(nonce)
				candidate.KeyCandidate.MixDigest = common.BytesToHash(digest)
				log.Info("mineCandidate", "foundedElapseTime", foundedElapseTime, "nonce", candidate.KeyCandidate.Nonce, "digest", candidate.KeyCandidate.MixDigest)

				// Seal and return a block (if still needed)
				select {
				case found <- candidate:
					log.Info("Ethash nonce found and reported", "attempts", nonce-seed, "nonce", nonce)
				case <-abort:
					logger.Trace("Ethash nonce found but discarded", "attempts", nonce-seed, "nonce", nonce)
				}
				break search
			}
			nonce++
		}
	}
	// Datasets are unmapped in a finalizer. Ensure that the dataset stays live
	// during sealing so it's not unmapped while being read.
	runtime.KeepAlive(dataset)
}
