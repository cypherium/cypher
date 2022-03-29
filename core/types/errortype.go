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

package types

import "errors"

var (
	ErrUnknownAncestor = errors.New("unknown ancestor")

	// types.ErrPrunedAncestor is returned when validating a block requires an ancestor
	// that is known, but the state of which is not available.
	ErrPrunedAncestor = errors.New("pruned ancestor")

	// types.ErrFutureBlock is returned when a block's timestamp is in the future according
	// to the current node.
	ErrFutureBlock  = errors.New("block in the future")
	ErrNotFindBlock = errors.New("can not find block")

	// types.ErrInvalidNumber is returned if a block's number doesn't equal it's parent's
	// plus one.
	ErrInvalidNumber = errors.New("invalid block number")

	// types.ErrKnownBlock is returned when a block to import is already known locally.
	ErrKnownBlock = errors.New("block already known")
	// types.ErrGasLimitReached is returned by the gas pool if the amount of gas required
	// by a transaction is higher than what's left in the block.
	ErrGasLimitReached = errors.New("gas limit reached")

	// types.ErrBlacklistedHash is returned if a block to import is on the blacklist.
	ErrBlacklistedHash = errors.New("blacklisted hash")

	// types.ErrNonceTooHigh is returned if the nonce of a transaction is higher than the
	// next one expected based on the local chain.
	ErrNonceTooHigh = errors.New("nonce too high")

	ErrEmptySignature = errors.New("signature is empty")

	ErrInvalidSignature = errors.New("invalid signature")

	ErrInvalidCommittee = errors.New("invalid committee")
	ErrSendNotTimeOut   = errors.New("send data error, time is not out")
	ErrNotRunning       = errors.New("is not running")

	ErrEncodeRLP = errors.New("block EncodeRLP error")
)
