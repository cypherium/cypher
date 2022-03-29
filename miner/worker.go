package miner

import (
	"math/big"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/reconfig/bftview"

	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/consensus/ethash"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/p2p/netutil"
	"github.com/cypherium/cypher/params"
)

const (
	resultQueueSize = 10
	// The number is referenced from the size of tx pool.
	chainHeadChanSize = 10
)

// Agent can register themself with the worker
type Agent interface {
	Work() chan<- *Work
	SetReturnCh(chan<- *Result)
	Start()
	Stop()
}

// Work is the workers current environment and holds
// all of the current state information
type Work struct {
	config *params.ChainConfig
	signer types.Signer

	keyBlock  *types.KeyBlock // todo: should be the latest key block header
	candidate *types.Candidate

	createdAt time.Time
}

type Result struct {
	Work      *Work
	Candidate *types.Candidate
}

// worker is the main object which takes care of applying messages to the new state
type worker struct {
	config *params.ChainConfig
	engine consensus.Engine

	candidatePool *core.CandidatePool
	mu            sync.Mutex

	// autoCommit loop
	mux        *event.TypeMux
	keyHeadCh  chan core.KeyChainHeadEvent // todo: should be the chain keyblock head
	keyHeadSub event.Subscription

	agents map[Agent]struct{}
	recv   chan *Result

	eth     Backend
	chain   *core.KeyBlockChain // todo: should be the key block
	chainDb ethdb.Database

	pubKey    ed25519.PublicKey
	coinBase  common.Address
	currentMu sync.Mutex
	current   *Work

	IP         []byte
	stopCommit chan chan bool

	// atomic status counters
	atWork  int32 // The number of in-flight pow engine work.
	running int32 // The indicator whether the pow engine is running or not.

	shouldStart int32 // should start indicates whether we should start after sync

}

func newWorker(config *params.ChainConfig, engine consensus.Engine, eth Backend, mux *event.TypeMux, candidatePool *core.CandidatePool, extIP net.IP) *worker {
	worker := &worker{
		config:        config,
		engine:        engine,
		eth:           eth,
		mux:           mux,
		keyHeadCh:     make(chan core.KeyChainHeadEvent, chainHeadChanSize),
		chainDb:       eth.ChainDb(),
		recv:          make(chan *Result, resultQueueSize),
		chain:         eth.KeyBlockChain(),
		agents:        make(map[Agent]struct{}),
		IP:            make(net.IP, len(extIP)),
		candidatePool: candidatePool,
		stopCommit:    make(chan chan bool, 1),
		running:       0,
		shouldStart:   0,
	}

	copy(worker.IP, extIP)
	go worker.wait()

	return worker
}
func (self *worker) setShouldStart(isStart bool) {
	if isStart {
		atomic.StoreInt32(&self.shouldStart, 1)

	} else {
		atomic.StoreInt32(&self.shouldStart, 0)
	}
}

func (self *worker) start() {
	self.mu.Lock()
	defer self.mu.Unlock()
	if atomic.LoadInt32(&self.running) == 1 {
		return
	}
	port, _ := strconv.Atoi(self.config.RnetPort)
	err := netutil.VerifyConnectivity("udp", net.ParseIP("127.0.0.1"), port)
	if err != nil {
		log.Error("Your node haven't opened UDP consensus port.So POW work is not to permit", "The port is", port)
		return
	}

	atomic.StoreInt32(&self.running, 1)
	self.keyHeadSub = self.eth.KeyBlockChain().SubscribeChainEvent(self.keyHeadCh)

	go self.autoCommit()

	for agent := range self.agents {
		agent.Start()
	}
}

func (self *worker) stop() {
	self.mu.Lock()
	defer self.mu.Unlock()
	if atomic.LoadInt32(&self.running) == 0 {
		return
	}

	self.keyHeadSub.Unsubscribe()

	atomic.StoreInt32(&self.running, 0)
	for agent := range self.agents {
		agent.Stop()
	}
	atomic.StoreInt32(&self.atWork, 0)
}

func (self *worker) isRunning() bool {
	return atomic.LoadInt32(&self.running) == 1
}

func (self *worker) register(agent Agent) {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.agents[agent] = struct{}{}
	agent.SetReturnCh(self.recv)
	if self.isRunning() {
		agent.Start()
	}
}

func (self *worker) unregister(agent Agent) {
	self.mu.Lock()
	defer self.mu.Unlock()
	delete(self.agents, agent)
	agent.Stop()
}

func (self *worker) autoCommit() {
	log.Info("Miner worker start auto-committing")
	if bftview.IamMember() < 0 {
		self.commitNewWork()
	}

	for {
		select {
		case <-self.keyHeadCh:
			if bftview.IamMember() < 0 {
				self.commitNewWork()
				self.stop()

				shouldStart := atomic.LoadInt32(&self.shouldStart) == 1
				if shouldStart {
					if !self.isRunning() {
						log.Info("Restore,Ready to start pow work")
						self.start() //now action
					}

				} else {
					if !shouldStart {
						log.Info("User has not permitted  to start")
					}
				}
			}

		// Err() channel will be closed when unsubscribing.
		case <-self.keyHeadSub.Err():
			log.Info("Miner worker stop auto-committing")
			return
		}
	}
}

func (self *worker) wait() {
	for {
		for result := range self.recv {
			atomic.AddInt32(&self.atWork, -1)

			if result == nil {
				continue
			}

			candidate := result.Candidate

			if err := self.engine.VerifyCandidate(self.chain, candidate); err != nil {
				log.Error("Fail to verify sealed candidate", "err", err)
				self.commitNewWork()
				continue
			}

			if err := self.candidatePool.AddLocal(candidate); err != nil {
				log.Error("Fail to add local candidate", "err", err)
				if err != core.ErrCandidateExisted && err != core.ErrCandidateIsMember {
					self.commitNewWork()
				}
			}

			if ethash.Mode(self.engine.PowMode()) == ethash.ModeLocalMock {
				self.LocalMockAutoTrigNextTermPow(candidate)
			}

		}
	}
}

// push sends a new work task to currently live miner agents.
func (self *worker) push(work *Work) {
	for agent := range self.agents {
		atomic.AddInt32(&self.atWork, 1)
		if ch := agent.Work(); ch != nil {
			ch <- work
		}
	}
}

// makeCurrent creates a new environment for the current cycle.
func (self *worker) makeCurrent(keyBlock *types.KeyBlock, candidate *types.Candidate) error {
	work := &Work{
		config:    self.config,
		signer:    types.NewEIP155Signer(self.config.ChainID),
		keyBlock:  keyBlock,
		candidate: candidate,
		createdAt: time.Now(),
	}

	self.current = work
	return nil
}

func (self *worker) commitNewWork() {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.currentMu.Lock()
	defer self.currentMu.Unlock()
	tstart := time.Now()
	keyBlock := self.chain.CurrentBlock() // todo: current keybBlock
	txBlock := self.eth.BlockChain().CurrentBlock()
	if txBlock.NumberU64() < keyBlock.T_Number() {
		log.Error("worker.commitNewWork is too low", "number", txBlock.NumberU64())
		return
	}
	if ethash.Mode(self.engine.PowMode()) != ethash.ModeLocalMock {
		if self.candidatePool.FoundCandidate(keyBlock.Number(), string(self.pubKey)) {
			log.Trace("Found existing candidate of head key block")
			return
		}
	}
	tstamp := tstart.Unix()
	kstamp := int64(keyBlock.Time())
	if kstamp >= tstamp {
		tstamp = kstamp + 1
	}
	// this will ensure we're not going off too far in the future
	if now := time.Now().Unix(); tstamp > now+1 {
		wait := time.Duration(tstamp-now) * time.Second
		log.Info("Mining too far in the future", "wait", common.PrettyDuration(wait))
		time.Sleep(wait)
	}

	port, _ := strconv.Atoi(self.config.RnetPort)
	candidate := types.NewCandidate(keyBlock.Hash(), nil, keyBlock.Number().Uint64()+uint64(1), txBlock.NumberU64(), nil, self.IP, common.HexString(self.pubKey), self.coinBase.String(), port)
	committeeSize := len(self.eth.KeyBlockChain().CurrentCommittee())

	if err := self.engine.PrepareCandidate(self.chain, candidate, committeeSize); err != nil {
		log.Error("Failed to prepare candidate for mining", "err", err)
		return
	}

	self.makeCurrent(keyBlock, candidate)
	work := self.current

	if self.isRunning() {
		//log.Info(fmt.Sprintf("Commit %d mining work", work.keyBlock.Number()), "elapsed", common.PrettyDuration(time.Since(tstart)))
		self.push(work)
	}
}

func (self *worker) SetPubKey(pubKey ed25519.PublicKey) {
	self.pubKey = pubKey
}

func (self *worker) SetCoinbase(eb common.Address) {
	self.coinBase = eb
}
func (self *worker) LocalMockAutoTrigNextTermPow(cand *types.Candidate) { //for debug

	block := self.chain.CurrentBlock()
	number := cand.KeyCandidate.Number
	block.SetNumber(number.Add(number, big.NewInt(1)))
	block.SetDifficulty(cand.KeyCandidate.Difficulty)
	block.Hash()
	block.SetTime(uint64(time.Now().Unix()))
	self.chain.CurrentBlockStore(block)
	//log.Info("LocalMockAutoTrigNextTermPow", "Next KeyBlcokNumber", block.Header().Number)
	self.commitNewWork()

}
