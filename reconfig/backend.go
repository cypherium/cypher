package reconfig

import (
	"net"
	"sync"
	"time"

	"github.com/cypherium/cypher/accounts"
	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/eth/downloader"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/node"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rpc"
)

// Backend wraps all methods required for mining.
type Backend interface {
	ChainDb() ethdb.Database
	BlockChain() *core.BlockChain
	KeyBlockChain() *core.KeyBlockChain
	TxPool() *core.TxPool
	AccountManager() *accounts.Manager
	GetCalcGasLimit() func(block *types.Block) uint64
	ConsensusServicePendingLogsFeed() *event.Feed

	CandidatePool() *core.CandidatePool
	Engine() consensus.Engine
	ExtIP() net.IP
}

type ReconfigBackend struct {
	blockchain     *core.BlockChain
	keyBlockchain  *core.KeyBlockChain
	chainDb        ethdb.Database // Block chain database
	txMu           sync.Mutex
	txPool         *core.TxPool
	accountManager *accounts.Manager
	downloader     *downloader.Downloader

	// we need an event mux to instantiate the blockchain
	eventMux         *event.TypeMux
	calcGasLimitFunc func(block *types.Block) uint64

	pendingLogsFeed *event.Feed
	candidatePool   *core.CandidatePool
	engine          consensus.Engine
	//-----------------------------------------------
	service *Service
}

// Public interface of service class
type serviceI interface {
	isRunning() bool
	updateCommittee(keyBlock *types.KeyBlock) bool
	procBlockDone(block *types.Block)
	GetCurrentView() *bftview.View
	getBestCandidate(refresh bool) *types.Candidate
	syncCommittee(mb *bftview.Committee, keyblock *types.KeyBlock)
	setNextLeader(isDone bool)
	sendNewViewMsg(curN uint64)
	LeaderAckTime() time.Time
	ResetLeaderAckTime()
	SwitchOK() bool
}

func New(stack *node.Node, chainConfig *params.ChainConfig, e Backend) (*ReconfigBackend, error) {
	backend := &ReconfigBackend{
		eventMux:         stack.EventMux(),
		chainDb:          e.ChainDb(),
		blockchain:       e.BlockChain(),
		keyBlockchain:    e.KeyBlockChain(),
		txPool:           e.TxPool(),
		accountManager:   e.AccountManager(),
		calcGasLimitFunc: e.GetCalcGasLimit(),
		pendingLogsFeed:  e.ConsensusServicePendingLogsFeed(),
		candidatePool:    e.CandidatePool(),
		engine:           e.Engine(),
	}
	sIp := e.ExtIP().String() + ":" + chainConfig.RnetPort
	//backend.minter = newMinter(chainConfig, backend, blockTime)
	backend.service = newService("cypherBFTService", sIp, chainConfig, backend)
	backend.candidatePool.CheckMinerPort = backend.CheckMinerPort

	stack.RegisterAPIs(backend.apis())
	stack.RegisterLifecycle(backend)

	return backend, nil
}

// Utility methods
func (backend *ReconfigBackend) apis() []rpc.API {
	return []rpc.API{
		{
			Namespace: "reconfig",
			Version:   "1.0",
			Service:   NewPublicReconfigAPI(backend),
			Public:    true,
		},
	}
}

// Backend interface methods:

func (backend *ReconfigBackend) AccountManager() *accounts.Manager  { return backend.accountManager }
func (backend *ReconfigBackend) BlockChain() *core.BlockChain       { return backend.blockchain }
func (backend *ReconfigBackend) KeyBlockChain() *core.KeyBlockChain { return backend.keyBlockchain }
func (backend *ReconfigBackend) ChainDb() ethdb.Database            { return backend.chainDb }
func (backend *ReconfigBackend) DappDb() ethdb.Database             { return nil }
func (backend *ReconfigBackend) EventMux() *event.TypeMux           { return backend.eventMux }
func (backend *ReconfigBackend) TxPool() *core.TxPool               { return backend.txPool }
func (backend *ReconfigBackend) CandidatePool() *core.CandidatePool { return backend.candidatePool }
func (backend *ReconfigBackend) Engine() consensus.Engine           { return backend.engine }
func (backend *ReconfigBackend) ConsensusServicePendingLogsFeed() *event.Feed {
	return backend.pendingLogsFeed
}

// node.Lifecycle interface methods:

// Start implements node.Service, starting the background data propagation thread
// of the protocol.
func (backend *ReconfigBackend) Start() error {
	return nil
}

// Stop implements node.Service, stopping the background data propagation thread
// of the protocol.
func (backend *ReconfigBackend) Stop() error {
	backend.service.stop()
	backend.blockchain.Stop()
	backend.eventMux.Stop()

	// handles gracefully if freezedb process is already stopped
	backend.chainDb.Close()

	log.Info("Raft stopped")
	return nil
}

//------------------------------------------------------------------
func (backend *ReconfigBackend) MinerStart(config *common.NodeConfig) error {
	backend.service.start(config)
	log.Info("reconfig start")
	return nil
}

func (backend *ReconfigBackend) MinerStop() error {
	backend.service.stop()
	log.Info("reconfig stop")
	return nil
}

//ReconfigIsRunning call by api
func (backend *ReconfigBackend) ServiceIsRunning() bool {
	return backend.service.isRunning()
}

func (backend *ReconfigBackend) Exceptions(blockNumber int64) []string {
	return backend.service.Exceptions(blockNumber)
}

func (backend *ReconfigBackend) CheckMinerPort(addr string, blockN uint64, keyblockN uint64) {
	backend.service.netService.CheckMinerPort(addr, blockN, keyblockN, 111)
}
