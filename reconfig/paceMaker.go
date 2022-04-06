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

package reconfig

import (

	//	"runtime"
	"sync"
	"time"

	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
//	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
)

var maxPaceMakerTime time.Time

type paceMakerTimer struct {
	startTime     time.Time
	lastKeyTime   time.Time
	beStop        bool
	beClose       bool
	service       serviceI
	txPool        *core.TxPool
	candidatepool *core.CandidatePool
	retryNumber   int
	config        *params.ChainConfig
	kbc           *core.KeyBlockChain
	mu            sync.Mutex

	//	txsCh  chan core.NewTxsEvent
	//	txsSub event.Subscription
}

func newPaceMakerTimer(config *params.ChainConfig, s serviceI, backend *ReconfigBackend) *paceMakerTimer {
	maxPaceMakerTime = time.Now().AddDate(200, 0, 0) //200 years
	t := &paceMakerTimer{
		service:       s,
		txPool:        backend.TxPool(),
		candidatepool: backend.CandidatePool(),
		startTime:     maxPaceMakerTime,
		lastKeyTime:   time.Now(),
		beStop:        true,
		beClose:       false,
		config:        config,
	}

	//	t.txsCh = make(chan core.NewTxsEvent, 128)
	//	t.txsSub = backend.TxPool().SubscribeNewTxsEvent(t.txsCh)
	//	go t.txsEventLoop()

	go t.loopTimer()
	return t
}

// Start for time counting of pacemake
func (t *paceMakerTimer) start() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.beStop { //first
		t.startTime = time.Now()
		/*
			if t.txPool.PendingCount() > 0 && t.service.SwitchOK() {
				t.startTime = time.Now()
			} else {
				now := time.Now()
				diff := now.Sub(t.lastKeyTime)
				if diff > params.KeyBlockTimeout {
					t.startTime = time.Now()
					log.Debug("paceMakerTimer keyblock", "startTime", t.startTime)
				}
			}
		*/
	} else {
		t.startTime = time.Now()
	}
	//log.Info("paceMakerTimer.start", "startTime", t.startTime )

	t.beStop = false

	return nil
}

// Stop for time counting of pacemake
func (t *paceMakerTimer) stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.beStop = true
	t.retryNumber = 0
	t.startTime = maxPaceMakerTime
	return nil
}

// Close pacemake loop
func (t *paceMakerTimer) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.beClose = true
}
func (t *paceMakerTimer) get() (time.Time, bool, bool, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.startTime, t.beStop, t.beClose, t.retryNumber
}

// Loop for status action
func (t *paceMakerTimer) loopTimer() {
	for {
		time.Sleep(50 * time.Millisecond)
		startTime, beStop, beClose, retryNumber := t.get()
		if beClose {
			return
		}

		if beStop || startTime == maxPaceMakerTime {
			continue
		}

		now := time.Now()
		diff := now.Sub(startTime)
		if diff > params.AckTimeout && now.Sub(t.service.LeaderAckTime()) > params.AckTimeout && bftview.IamMember() >= 0 {
			log.Warn("paceMakerTimer Viewchange AckTimeout")
			t.setNextLeader(false)
			t.service.ResetLeaderAckTime()
		} else if diff > params.PaceMakerTimeout /**time.Duration(retryNumber+1)*/ && bftview.IamMember() >= 0 { //timeout
			log.Warn("paceMakerTimer Viewchange PaceMakerTimeout Event is coming", "retryNumber", retryNumber)
			/*
				switchLen := bftview.GetServerCommitteeLen()/2 + 1
				if t.retryNumber > switchLen && t.retryNumber%switchLen == 0 {
					log.Warn("Viewchange Event is coming", "double wait, retryNumber", retryNumber, "committee len", bftview.GetServerCommitteeLen())
					t.start()
					continue
				}
			*/
			t.setNextLeader(false)
			t.retryNumber++
		}
	}
}

func (t *paceMakerTimer) setNextLeader(isDone bool) {
	curView := t.service.GetCurrentView()
	t.service.setNextLeader(isDone)
	t.service.sendNewViewMsg(curView.TxNumber)
	t.start()
}

var m_totalTxs int
var m_tps10StartTm time.Time

// Event for new block done
func (t *paceMakerTimer) procBlockDone(curBlock *types.Block, curKeyBlock *types.KeyBlock, isKeyBlock bool) {
	if isKeyBlock {
		t.lastKeyTime = time.Now()
		log.Debug("paceMakerTimer keyblock done", "lastKeyTime", t.lastKeyTime)
	}
	if curBlock != nil {
		if t.config.EnabledTPS {
			txs := len(curBlock.Transactions())
			m_totalTxs += txs
			if txs > 0 {
				now := time.Now()
				if m_tps10StartTm.Equal(time.Time{}) {
					m_tps10StartTm = now
				} else if now.Sub(m_tps10StartTm).Seconds() > 10 {
					tps := float64(m_totalTxs) / now.Sub(m_tps10StartTm).Seconds()
					log.Debug("@TPS10", "txs/s", tps)
					m_totalTxs = 0
					m_tps10StartTm = now
				}
				tps := float64(txs) / now.Sub(t.startTime).Seconds()
				log.Debug("@TPS", "txs/s", tps)
			}
		}

		n := curBlock.NumberU64() - curKeyBlock.T_Number()
		if n > 0 && n%params.KeyblockPerTxBlocks == 0 {
			t.setNextLeader(true)
		}

		//if curBlock.NumberU64()%20 == 0 {
		//log.Info("Goroutine", "num", runtime.NumGoroutine())
		//runtime.GC() //force gc
		//}

	}

	t.stop()
	if bftview.IamMember() >= 0 {
		t.start()
	}

}

/*
func (t *paceMakerTimer) txsEventLoop() {
	for {
		select {
		case <-t.txsCh: // Event for New TXS coming
			//log.Debug("core.NewTxsEvent")
			t.mu.Lock()
			if t.beStop || t.beClose {
				t.mu.Unlock()
				return
			}
			if t.startTime == maxPaceMakerTime {
				t.startTime = time.Now()
			}
			t.mu.Unlock()

		case <-t.txsSub.Err():
			log.Info("txsEventLoop stopped")
			return
		}
	}
}
*/
