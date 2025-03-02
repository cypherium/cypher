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
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/event"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/reconfig/hotstuff"
	"github.com/cypherium/cypher/rnet/network"
)

type committeeInfo struct {
	Committee *bftview.Committee
	KeyHash   common.Hash
	KeyNumber uint64
}
type bestCandidateInfo struct {
	Node      *common.Cnode
	KeyHash   common.Hash
	KeyNumber uint64
}
type cachedCommitteeInfo struct {
	keyHash   common.Hash
	keyNumber uint64
	committee *bftview.Committee
	node      *common.Cnode
}
type committeeMsg struct {
	sid   *network.ServerIdentity
	cinfo *committeeInfo
	best  *bestCandidateInfo
}
type hotstuffMsg struct {
	sid   *network.ServerIdentity
	lastN uint64
	hMsg  *hotstuff.HotstuffMessage
}

type networkMsg struct {
	MsgFlag uint32
	Hmsg    *hotstuff.HotstuffMessage
	Cmsg    *committeeInfo
	Bmsg    *bestCandidateInfo
}

func (msg *networkMsg) GetCommittee() *bftview.Committee {
	var mb *bftview.Committee
	if msg.Cmsg != nil {
		mb = bftview.LoadMember(msg.Cmsg.KeyNumber, msg.Cmsg.KeyHash, true)
	} else if msg.Bmsg != nil {
		mb = bftview.LoadMember(msg.Bmsg.KeyNumber, msg.Bmsg.KeyHash, true)
	} else if msg.Hmsg != nil {
		mb = bftview.GetCurrentMember()
	}
	return mb
}

//Service work for protcol
type Service struct {
	netService *netService
	bc         *core.BlockChain
	txService  *txService
	kbc        *core.KeyBlockChain
	keyService *keyService
	txPool     *core.TxPool

	protocolMng *hotstuff.HotstuffProtocolManager

	lastCmInfoMap   map[common.Hash]*cachedCommitteeInfo
	muCommitteeInfo sync.Mutex
	currentView     bftview.View
	waittingView    bftview.View
	lastReqCmNumber uint64
	muCurrentView   sync.Mutex

	replicaView     *bftview.View
	runningState    int32
	lastProposeTime time.Time
	pacetMakerTimer *paceMakerTimer

	hotstuffMsgQ *common.Queue
	feed1        event.Feed
	msgCh1       chan committeeMsg
	msgSub1      event.Subscription // Subscription for msg event
}

func newService(sName, sIp string, chainConfig *params.ChainConfig, backend *ReconfigBackend) *Service {
	s := new(Service)
	s.netService = newNetService(sName, sIp, chainConfig, backend, s)
	s.txService = newTxService(s, backend, chainConfig)
	s.keyService = newKeyService(s, backend, chainConfig)

	s.bc = backend.BlockChain()
	s.kbc = backend.KeyBlockChain()
	s.txPool = backend.TxPool()

	s.lastCmInfoMap = make(map[common.Hash]*cachedCommitteeInfo)

	s.msgCh1 = make(chan committeeMsg, 10)
	s.msgSub1 = s.feed1.Subscribe(s.msgCh1)
	s.hotstuffMsgQ = common.QueueNew()

	s.protocolMng = hotstuff.NewHotstuffProtocolManager(s, nil, nil)
	s.pacetMakerTimer = newPaceMakerTimer(chainConfig, s, backend)

	bftview.SetCommitteeConfig(backend.ChainDb(), backend.KeyBlockChain(), s)

	go s.handleHotStuffMsg()
	go s.handleCommitteeMsg()
	return s
}

//OnNewView --------------------------------------------------------------------------
func (s *Service) OnNewView(data []byte, extraes [][]byte) error { //buf is snapshot, //verify repla' block before newview
	view := bftview.DecodeToView(data)
	log.Info("OnNewView..", "txNumber", view.TxNumber, "keyNumber", view.KeyNumber)

	s.muCurrentView.Lock()
	s.replicaView = view
	if view.EqualNoIndex(&s.currentView) {
		s.currentView.LeaderIndex = view.LeaderIndex
	}
	s.muCurrentView.Unlock()

	var bestCandidates []*types.Candidate
	for _, extraD := range extraes {
		if extraD == nil {
			continue
		}
		cand := types.DecodeToCandidate(extraD)
		if cand == nil {
			continue
		}
		bestCandidates = append(bestCandidates, cand)
	}
	s.keyService.setBestCandidate(bestCandidates)
	return nil
}

func (s *Service) CurrentN() uint64 {
	curView := s.GetCurrentView()
	return curView.TxNumber + 1
}

//CurrentState call by hotstuff
func (s *Service) CurrentState() ([]byte, string, uint64) { //recv by onnewview
	curView := s.GetCurrentView()
	leaderID := ""
	mb := bftview.GetCurrentMember()
	if mb != nil {
		leader := mb.List[curView.LeaderIndex]
		//leader := mb.List[0]
		log.Info("CurrentState.NextLeader", "index", curView.LeaderIndex, "ip", leader.Address)
		leaderID = bftview.GetNodeID(leader.Address, leader.Public)
	} else {
		log.Error("CurrentState.NextLeader: can't get current committee!, set dedault")
		keyblock := s.kbc.GetBlockByNumber(curView.KeyNumber)
		var mbNew = new(bftview.Committee)
		mbNew.List = []*common.Cnode{
			&common.Cnode{
				Address:  "61.29.244.73:7100",
				CoinBase: "0x83ea72f02b82199b29cae3118e163f3a05ef4b16",
				Public:   "139f38608c03b9a7799761afa93d1639735f561b3455f27be34018ad1455c90801d138c61b9f157c5f00b2dee0fc81256bfd9d413380963f77711b477696af04",
			},
			&common.Cnode{
				Address:  "61.29.244.66:7100",
				CoinBase: "0x999086e1149346e803535e7176e6ce8658883f33",
				Public:   "7993a80aa84986113d82708b3b2ec36f7b089da90489d8dea3aaf52fabee7a17205500ff3e0425d196729f0612a36a02c74a6763b17142feffda8d9181314d96",
			},
			&common.Cnode{
				Address:  "61.29.244.77:7100",
				CoinBase: "0x693ca592fa363109dc8b5e8a9a0c8d467d4e69a6",
				Public:   "a52b9830ca9f3cda0e7d78db4dd891b5dce05fb637164e5c68e73265ff6bd922c049cbb7f77fcde2dfd062881c486ff5b953aa02f883d234b8437e56df472da2",
			},
			&common.Cnode{
				Address:  "61.29.244.76:7100",
				CoinBase: "0x41fb9fdf1db61b4594e3ef0b27a6840f3d2e9208",
				Public:   "bf20503a2ab1f6d957e43c675bc2f25bc23739a7c388d23c2faedb32aa7c771e2380a1ed03cd2ebec6b09a402b7c3d1f61969926b79d91a52cc1cefbabf331a4",
			},
			&common.Cnode{
				Address:  "61.29.244.76:7100",
				CoinBase: "0x31cf88e26297545abdf1e6c1f8fb041cebb89290",
				Public:   "c0ac9fdb18faebfb9dc4d77731904acec5020e4fdd610d1e68a35b38e372cd0b883853f86b0a79e8ae0203f43a1107dbc7c0023ea3fb7b1abc15a3ce6896c586",
			},
			&common.Cnode{
				Address:  "61.29.244.13:7100",
				CoinBase: "0x630484e88ba61ba42f98f81bd5981e48b3547a58",
				Public:   "26ae6fbf46f2b75324631e55ff614c12726071e171d3c285ec4a27e33688b51ce5c24fcdbb09bc9f277546a210acad449f94b64a01cc5e577de9480b8272f49b",
			},
			&common.Cnode{
				Address:  "61.29.244.62:7100",
				CoinBase: "0xc3a86479301b07a5849e382418fd524fc9e88fbe",
				Public:   "ae633456e1e48a2c22a2d71cb7c708423f8881528672897a720e88992943091f7c8325f633e854e05ff07f9f6b7a66fadb95f17acfd0904b4a025753ce4a7412",
			},
			&common.Cnode{
				Address:  "61.29.244.65:7100",
				CoinBase: "0xca6df652714911b4c6d14881c143cc09e9ad61c0",
				Public:   "fafb82c0e658423ac0462d0895dd03b490ead2d148a281eb72ab101b6a58d60e97a718eb14f7a50e2b8a60884ce6c456ac27c16c58bfa7dcd9b006f34e463487",
			},
			&common.Cnode{
				Address:  "61.29.244.68:7100",
				CoinBase: "0x9ffedc42447cb915de3edf1593e81e95c06b408b",
				Public:   "ece5494aa77c14c699403871c3156b510e3ca0db08d625a189075503ec59001e6a6a359ac3d9232f96f21969f758262ec50b670a1d19827ec2f93fe4e017c502",
			},
			&common.Cnode{
				Address:  "61.29.244.60:7100",
				CoinBase: "0x737868db41e87d0dc7a694f7d401f016203e3d3b",
				Public:   "0ba57567572370db0722d2bb238a39605f6a3949b0fb660f2b36ad799cfdcd0e2d20a4cc1f111fdd1efda1af8b9d2136b108b617bc26e157465b34c46582cd8e",
			},
			&common.Cnode{
				Address:  "61.29.244.50:7100",
				CoinBase: "0xca0b3882b1e0a1540cfef7364ccf2ed8027fa86d",
				Public:   "d144b3e223a9a2868eb603446339c2d4372553d3451f10c7440c48e947e7fc1d2a4507a5ee46517f8b56a793dde13e8f6eeb7e49293c06fe66ca10d00c0a23a3",
			},
			&common.Cnode{
				Address:  "61.29.244.67:7100",
				CoinBase: "0x7cb40ba4a764d646100c5a9c058791b26ffbf96e",
				Public:   "2d8d22bb4a873f224d6a101a9fa24c614aea403ed5025e33c6da756a1507ea1c0ab37803475a23964b5f8649046f3a26c79863e2c567e6aedaffdac408438722",
			},
			&common.Cnode{
				Address:  "61.29.244.48:7100",
				CoinBase: "0x8c22b884c3f774dcd4f0cc4c6e920bd23b5d513f",
				Public:   "76c04ea4a0c0ee12a473b2d64a5e7c205d1837118619cfc811a1ee0cff929d1d50f6881c7af9e954aaadd3f0feea4c8d0405f454daeff79b9cee25fdbea6b51c",
			},
			&common.Cnode{
				Address:  "61.29.244.75:7100",
				CoinBase: "0x597fe78278722f5d96ba85bb66d67785015cbb8a",
				Public:   "5f715f77e352265d6b115fc36fe9b44700241c1300279e773f6ec2c8882a761e193785ce51a107ccf711eda85b7a51bb0a6fd6951520a67b8b0d6983c2b74e10",
			},
			&common.Cnode{
				Address:  "61.29.244.72:7100",
				CoinBase: "0x10ca2b7e3e26801e2a78c67000ac1982cb8b709e",
				Public:   "07223ea877650813afe8e5c1a4b7556931620fbbaed50db387b66c44b9d40e10652d18d6b8112d4f49b92fdf2195ac801a022c2ef0155418e7b0a01b8126f903",
			},
			&common.Cnode{
				Address:  "61.29.244.57:7100",
				CoinBase: "0x05c6aca0ab3e47c7515c93ea563dbaf8861d5d5f",
				Public:   "ee1b323335cba981e97e727bf718b3e160d0eae9f47af11ac4279dcce0067213040d9fca2ae842fb0cbc9c3f687414317d7589a2761014587b88c14f3cca1783",
			},
			&common.Cnode{
				Address:  "61.29.244.53:7100",
				CoinBase: "0xcab788f0767a3b62c33fe25ee3e87a94c0403f8e",
				Public:   "39fd9293185505b15c006c857fc39a148256edd998326fb998e7db224202f00769aae37d63287828c28181f0cb41dfcdd535d4e27f6c015592bd5a99fe4ef01e",
			},
			&common.Cnode{
				Address:  "61.29.244.48:7100",
				CoinBase: "0x52cd8c3a22a91b93b672f8d10e19d1c6fbe1ae42",
				Public:   "f2ea475b700ff366a21fdeb13d9701e9546270fe189cb52b7cdcd5a906d73e23fd0788af82e3f10be9f94ad076cc040ba4e37fc4f6c81746a54f4754d5354e18",
			},
			&common.Cnode{
				Address:  "61.29.244.63:7100",
				CoinBase: "0xaf006145afceb9b3f34c03b16893c98b72160323",
				Public:   "0fb677ab80eb75ec8f3eb15ec8697a80ef9a0cb4c4ad742b543b3b4f23ac8405df6b9526b0e0f2c601cb6c61d44a2d3f04a5838809adc85106ae78c19da7590c",
			},
			&common.Cnode{
				Address:  "61.29.244.57:7100",
				CoinBase: "0x5a3c2b79faa6cf64a33a701f345e96911112cbbd",
				Public:   "7b3b3d5f707068cd9ed515bba04dd732d8890ff2ba04c858ffec95e527874b10b1593686e3a8da9dd77bafbbd82830dd4c4108ef9c585d0356a3dacb3a47cd80",
			},
			&common.Cnode{
				Address:  "61.29.244.64:7100",
				CoinBase: "0x2d1e776d5ce8906dca30635819609b2bb2de245c",
				Public:   "e63d028382972a19d92fc19ed62bf71cd4585b09cf36577140cce80ce13f07018c21fabc109a83fa59e60d75dafc76aacfe7a5ef47960a7e04701d4cd64b12a3",
			},
		}
		mbNew.Store(keyblock)

		leader := mbNew.List[curView.LeaderIndex]
		log.Info("mbNew CurrentState.NextLeader", "index", curView.LeaderIndex, "ip", leader.Address)
		leaderID = bftview.GetNodeID(leader.Address, leader.Public)
		//s.Committee_Request(curView.KeyNumber, curView.KeyHash)
	}

	log.Info("CurrentState", "TxNumber", curView.TxNumber, "KeyNumber", curView.KeyNumber, "LeaderIndex", curView.LeaderIndex, "NoDone", curView.NoDone)

	return curView.EncodeToBytes(), leaderID, curView.TxNumber + 1
}

//GetExtra call by hotstuff
func (s *Service) GetExtra() []byte {
	best := s.keyService.getBestCandidate(true)
	if best == nil {
		return nil
	}
	return best.EncodeToBytes()
}

//GetPublicKey call by hotstuff
func (s *Service) GetPublicKey() []*bls.PublicKey {
	keyblock := s.kbc.CurrentBlock()
	keyNumber := keyblock.NumberU64()
	c := bftview.LoadMember(keyNumber, keyblock.Hash(), false)
	if c == nil {
		return nil
	}
	return c.ToBlsPublicKeys(keyblock.Hash())
}

//Self call by hotstuff
func (s *Service) Self() string {
	return s.netService.serverID
}

//CheckView call by hotstuff
func (s *Service) CheckView(data []byte) error {
	if !s.isRunning() {
		return types.ErrNotRunning
	}
	view := bftview.DecodeToView(data)
	knumber := s.kbc.CurrentBlockN()
	txnumber := s.bc.CurrentBlockN()
	log.Debug("CheckView..", "txNumber", view.TxNumber, "keyNumber", view.KeyNumber, "local key number", knumber, "tx number", txnumber)
	if view.KeyNumber < knumber {
		return hotstuff.ErrOldState
	} else if view.KeyNumber > knumber {
		return hotstuff.ErrFutureState
	}
	if view.TxNumber < txnumber {
		return hotstuff.ErrOldState
	} else if view.TxNumber > txnumber {
		return hotstuff.ErrFutureState
	}

	return nil
}

//OnPropose call by hotstuff
func (s *Service) OnPropose(state []byte, extra []byte) error { //verify new block
	log.Debug("OnPropose..")
	if !s.isRunning() {
		return types.ErrNotRunning
	}

	var block *types.Block
	if state != nil {
		block = types.DecodeToBlock(state)
		log.Info("OnPropose", "txNumber", block.NumberU64())
	}
	if block != nil {
		err := s.txService.verifyTxBlock(block)
		if err != nil {
			log.Error("verify txblock", "number", block.NumberU64(), "err", err)
			return err
		}
		if block.BlockType() == types.Key_Block {
			kblock := types.DecodeToKeyBlock(block.KeyInfo())
			if kblock == nil {
				return fmt.Errorf("Block's extra (keyblock) is error format!")
			}
			err := s.keyService.verifyKeyBlock(kblock, types.DecodeToCandidate(extra))
			if err != nil {
				log.Error("verify keyblock", "number", kblock.NumberU64(), "err", err)
				return err
			}
		}
	} else {
		err := fmt.Errorf("DecodeToBlock(state) error")
		log.Error("Propose", "error", err)
		return err
	}
	s.pacetMakerTimer.start()
	return nil
}

//Propose call by hotstuff
func (s *Service) Propose() (e error, kState []byte, tState []byte, extra []byte) { //buf recv by onpropose, onviewdown
	log.Debug("Propose..", "number", s.currentView.TxNumber)

	proposeOK := false
	defer func() {
		if !proposeOK {
			go func() {
				time.Sleep(2 * time.Second)
				curView := s.GetCurrentView()
				if bftview.IamLeader(curView.LeaderIndex) {
					s.hotstuffMsgQ.PushBack(&hotstuffMsg{sid: nil, lastN: s.bc.CurrentBlockN(), hMsg: &hotstuff.HotstuffMessage{Code: hotstuff.MsgTryPropose}})
				}
			}()
		} else {
			s.lastProposeTime = time.Now()
		}
	}()

	if !s.isRunning() {
		err := fmt.Errorf("not running for propose")
		return err, nil, nil, nil
	}

	s.muCurrentView.Lock()
	leaderIndex := s.currentView.LeaderIndex
	if !s.replicaView.EqualAll(&s.currentView) {
		log.Error("Propose", "replica view not equal to local current view txNumber", s.currentView.TxNumber, "keyNumber", s.currentView.KeyNumber, "LeaderIndex", leaderIndex, "NoDone",
			s.currentView.NoDone, "replica txNumber", s.replicaView.TxNumber, "keyNumber", s.replicaView.KeyNumber, "LeaderIndex", s.replicaView.LeaderIndex, "NoDone", s.replicaView.NoDone)
		s.muCurrentView.Unlock()
		return fmt.Errorf("replica view not equal to local current view"), nil, nil, nil
	}
	if !bftview.IamLeader(leaderIndex) {
		//proposeOK = true
		err := fmt.Errorf("not leader for propose")
		log.Error("Propose", "leaderIndex", leaderIndex, "error", err)
		s.muCurrentView.Unlock()
		return err, nil, nil, nil
	}
	s.muCurrentView.Unlock()

	if leaderIndex > 0 {
		keyblock, mb, bestCandi, err := s.keyService.tryProposalChangeCommittee(leaderIndex, !s.currentView.NoDone)
		if err == nil && keyblock != nil && mb != nil {
			if bestCandi != nil {
				extra = bestCandi.EncodeToBytes()
			}
			data, err := s.txService.tryProposalNewKeyBlock(keyblock)
			if err != nil {
				log.Warn("tryProposalNewBlock", "error", err)
				return err, nil, nil, nil
			}
			proposeOK = true
			return nil, nil, data, extra
		} else {
			log.Error("tryProposalChangeCommittee failed", "error", err)
			return fmt.Errorf("tryProposalChangeCommittee failed"), nil, nil, nil
		}
	}
	data, err := s.txService.tryProposalNewBlock(types.Normal_Block)
	if err != nil {
		log.Warn("tryProposalNewBlock", "error", err)
		return err, nil, nil, nil
	}
	proposeOK = true
	return nil, nil, data, nil
}

//OnViewDone call by hotstuff
func (s *Service) OnViewDone(tSign *hotstuff.SignedState) error {
	if !s.isRunning() {
		return types.ErrNotRunning
	}
	if tSign == nil {
		log.Warn("OnViewDone nil!")
		return nil
	}
	block := types.DecodeToBlock(tSign.State)
	err := s.txService.decideNewBlock(block, tSign.Sign, tSign.Mask)
	if err != nil {
		return err
	}

	return nil
}

//Write call by hotstuff------------------------------------------------------------------------------------------------
func (s *Service) Write(id string, data *hotstuff.HotstuffMessage) error {
	log.Info("Write", "to id", id, "code", hotstuff.ReadableMsgType(data.Code), "ViewId", data.ViewId)

	if id == s.Self() {
		s.hotstuffMsgQ.PushBack(&hotstuffMsg{sid: nil, hMsg: data})
		return nil
	}

	mb := bftview.GetCurrentMember()
	if mb == nil {
		return fmt.Errorf("can't find current committee,id %s", id)
	}
	node, _ := mb.Get(id, bftview.ID)
	if node == nil || len(node.Address) < 7 { //1.1.1.1
		err := fmt.Errorf("can't find id %s in current committee", id)
		log.Error("Couldn't send", "err", err)
		return err
	}

	s.netService.SendRawData(node.Address, &networkMsg{Hmsg: data})
	return nil
}

//Broadcast call by hotstuff
func (s *Service) Broadcast(data *hotstuff.HotstuffMessage) []error {
	log.Debug("Broadcast", "code", hotstuff.ReadableMsgType(data.Code), "ViewId", data.ViewId)
	s.hotstuffMsgQ.PushBack(&hotstuffMsg{sid: nil, hMsg: data})
	/*
		mb := bftview.GetCurrentMember()
		if mb == nil {
			return []error{fmt.Errorf("can't find current committee")}
		}
		for _, node := range mb.List {
			if IsSelf(node.Address) {
				continue
			}
			s.netService.SendRawData(node.Address, &networkMsg{Hmsg: data})
		}
	*/
	s.netService.broadcast("", &networkMsg{Hmsg: data})
	return nil //return arr
}

func (s *Service) networkMsgAck(si *network.ServerIdentity, msg *networkMsg) {
	if msg.Hmsg != nil {
		s.hotstuffMsgQ.PushBack(&hotstuffMsg{sid: si, hMsg: msg.Hmsg})
		return
	}
	s.feed1.Send(committeeMsg{sid: si, cinfo: msg.Cmsg, best: msg.Bmsg})
}

func (s *Service) handleHotStuffMsg() {
	for {
		data := s.hotstuffMsgQ.PopFront()
		if data == nil {
			time.Sleep(100 * time.Millisecond)
			s.protocolMng.HandleMessage(&hotstuff.HotstuffMessage{Code: hotstuff.MsgTimer, Number: s.bc.CurrentBlockN()})
			continue
		}
		msg := data.(*hotstuffMsg)
		msgCode := msg.hMsg.Code
		log.Debug("handleHotStuffMsg", "id", msg.hMsg.Id, "code", hotstuff.ReadableMsgType(msgCode), "ViewId", msg.hMsg.ViewId)

		var curN uint64
		if msgCode == hotstuff.MsgTryPropose || msgCode == hotstuff.MsgStartNewView {
			curN = s.bc.CurrentBlockN()
			if msg.lastN < curN {
				log.Debug("handleHotStuffMsg", "code", hotstuff.ReadableMsgType(msgCode), "lastN", msg.lastN, "curN", curN)
				continue
			}
		} else if msgCode == hotstuff.MsgPrepare && msg.sid != nil {
			curBlock := s.kbc.CurrentBlock()
			keyNumber := curBlock.NumberU64()
			keyHash := curBlock.Hash()
			msgAddress := msg.sid.Address.String()
			if bftview.LoadMember(keyNumber, keyHash, true) == nil && msgAddress != s.netService.serverAddress {
				log.Debug("request committee", "keynumber", keyNumber, "send to address", msgAddress)
				s.netService.SendRawData(msgAddress, &networkMsg{Cmsg: &committeeInfo{Committee: nil, KeyHash: keyHash, KeyNumber: keyNumber}})
			}
		}

		err := s.protocolMng.HandleMessage(msg.hMsg)
		if err != nil && msgCode == hotstuff.MsgStartNewView {
			go func(curN uint64) {
				time.Sleep(2 * time.Second)
				s.sendNewViewMsg(curN)
			}(curN)
		}
	}
}

//-------------------------------------------------------------------------------------------------------------------------
func (s *Service) syncCommittee(mb *bftview.Committee, keyblock *types.KeyBlock) {
	if !keyblock.HasNewNode() {
		return
	}

	in := mb.In()
	s.netService.SendRawData(in.Address, &networkMsg{Cmsg: &committeeInfo{Committee: mb, KeyHash: keyblock.Hash(), KeyNumber: keyblock.NumberU64()}})

	msg := &bestCandidateInfo{Node: in, KeyHash: keyblock.Hash(), KeyNumber: keyblock.NumberU64()}
	//s.netService.broadcast("", &networkMsg{Bmsg: msg})
	for i, r := range mb.List {
		if i == 0 || IsSelf(r.Address) {
			continue
		}
		log.Debug("syncBestCandidate", "send to", r.Address)
		s.netService.SendRawData(r.Address, &networkMsg{Bmsg: msg})
	}
}

func (s *Service) storeCommitteeInCache(cmInfo *committeeInfo, best *bestCandidateInfo) {
	s.muCommitteeInfo.Lock()
	defer s.muCommitteeInfo.Unlock()
	var (
		keyHash   common.Hash
		keyNumber uint64
		committee *bftview.Committee
		node      *common.Cnode
	)
	if cmInfo != nil {
		keyHash = cmInfo.KeyHash
		keyNumber = cmInfo.KeyNumber
		committee = cmInfo.Committee
	} else if best != nil {
		keyHash = best.KeyHash
		keyNumber = best.KeyNumber
		node = best.Node
	}

	ac, ok := s.lastCmInfoMap[keyHash]
	if ok {
		if cmInfo != nil {
			ac.committee = cmInfo.Committee
		}
		if best != nil {
			ac.node = best.Node
		}
		return
	}
	//clear prev map
	maxNumber := s.kbc.CurrentBlockN()
	for hash, ac := range s.lastCmInfoMap {
		if ac.keyNumber < maxNumber-9 {
			delete(s.lastCmInfoMap, hash)
		}
	}
	log.Info("@@storeCommitteeInCache", "key number", keyNumber)

	s.lastCmInfoMap[keyHash] = &cachedCommitteeInfo{keyHash: keyHash, keyNumber: keyNumber, committee: committee, node: node}
}

// handle committee sync message
func (s *Service) handleCommitteeMsg() {
	for {
		select {
		case msg := <-s.msgCh1:
			if msg.best != nil {
				if bftview.LoadMember(msg.best.KeyNumber, msg.best.KeyHash, true) != nil {
					continue
				}
				log.Info("bestCandidate", "best KeyNumber", msg.best.KeyNumber)
				s.storeCommitteeInCache(nil, msg.best)
				continue
			}
			cInfo := msg.cinfo
			if cInfo == nil {
				continue
			}
			if cInfo.Committee == nil {
				mb := bftview.LoadMember(cInfo.KeyNumber, cInfo.KeyHash, true)
				if mb == nil {
					continue
				}
				msgAddress := msg.sid.Address.String()
				log.Debug("committeeInfo answer", "number", cInfo.KeyNumber, "adddress", msgAddress)
				r, _ := mb.Get(msgAddress, bftview.Address)
				if r != nil {
					log.Debug("committeeInfo answer..ok", "number", cInfo.KeyNumber)
					s.netService.SendRawData(msgAddress, &networkMsg{Cmsg: &committeeInfo{Committee: mb, KeyHash: cInfo.KeyHash, KeyNumber: cInfo.KeyNumber}})
				}
				continue
			}

			if bftview.LoadMember(cInfo.KeyNumber, cInfo.KeyHash, true) != nil {
				continue
			}
			log.Debug("committeeInfo", "number", cInfo.KeyNumber, "adddress", msg.sid.Address)
			keyblock := s.kbc.GetBlock(cInfo.KeyHash, cInfo.KeyNumber)
			if keyblock != nil {
				cInfo.Committee.Store(keyblock)
			} else {
				s.storeCommitteeInCache(cInfo, nil)
			}

		case <-s.msgSub1.Err():
			log.Error("handleHotStuffMsg Feed error")
			return
		}
	}
}

// Save committee by keyblock
func (s *Service) saveCommittee(curKeyBlock *types.KeyBlock) {
	mb := bftview.LoadMember(curKeyBlock.NumberU64(), curKeyBlock.Hash(), false)
	if mb != nil {
		return
	}

	var newNode *common.Cnode
	if curKeyBlock.BlockType() == types.PowReconfig || curKeyBlock.BlockType() == types.PacePowReconfig {
		newNode = &common.Cnode{
			CoinBase: curKeyBlock.InAddress(),
			Public:   curKeyBlock.InPubKey(),
		}
	}

	mb, _ = bftview.GetCommittee(newNode, curKeyBlock, false)
	mb.Store0(curKeyBlock)
}

// Update committee by keyblock
func (s *Service) updateCommittee(keyBlock *types.KeyBlock) bool {
	bStore := false
	curKeyBlock := keyBlock
	if bftview.IamMember() < 0 {
		return false
	}
	if curKeyBlock == nil {
		curKeyBlock = s.kbc.CurrentBlock()
	}
	mb := bftview.LoadMember(curKeyBlock.NumberU64(), curKeyBlock.Hash(), true)
	if mb != nil {
		return bStore
	}

	s.muCommitteeInfo.Lock()
	ac, ok := s.lastCmInfoMap[curKeyBlock.Hash()]
	if ok {
		if ac.committee != nil {
			mb = ac.committee
		} else if ac.node != nil {
			mb, _ = bftview.GetCommittee(ac.node, curKeyBlock, true)
		}
	}
	s.muCommitteeInfo.Unlock()

	if mb == nil && !curKeyBlock.HasNewNode() {
		mb, _ = bftview.GetCommittee(nil, curKeyBlock, true)
	}

	if mb != nil {
		bStore = mb.Store(curKeyBlock)
	} else {
		log.Info("updateCommittee can't found committee", "txNumber", s.bc.CurrentBlockN(), "keyNumber", curKeyBlock.NumberU64())
	}
	return bStore
}

func (s *Service) Committee_OnStored(keyblock *types.KeyBlock, mb *bftview.Committee) {
	log.Debug("store committee", "keyNumber", keyblock.NumberU64(), "ip0", mb.List[0].Address, "ipn", mb.List[len(mb.List)-1].Address)
	if keyblock.HasNewNode() && keyblock.NumberU64() == s.kbc.CurrentBlockN() {
		s.netService.AdjustConnect(keyblock.OutAddress(1))
	}
}

// Request committee for keyblock
func (s *Service) Committee_Request(kNumber uint64, hash common.Hash) {
	if kNumber <= s.lastReqCmNumber || !bftview.IamMemberByNumber(kNumber, hash) {
		return
	}

	log.Debug("Committee_Request", "keynumber", kNumber)

	var parentMb *bftview.Committee
	for i := 1; i < 10; i++ {
		keyblock := s.kbc.GetBlockByNumber(kNumber - uint64(i))
		if keyblock == nil {
			return
		}
		mb := bftview.LoadMember(keyblock.NumberU64(), keyblock.Hash(), true)
		if mb != nil {
			parentMb = mb
			break
		}
	}
	if parentMb == nil {
		return
	}

	for _, node := range parentMb.List {
		if IsSelf(node.Address) {
			continue
		}
		s.netService.SendRawData(node.Address, &networkMsg{Cmsg: &committeeInfo{Committee: nil, KeyHash: hash, KeyNumber: kNumber}})
	}
	s.lastReqCmNumber = kNumber
}

// Update current view data
func (s *Service) updateCurrentView(curBlock *types.Block, curKeyBlock *types.KeyBlock, fromKeyBlock bool) { //call by keyblock done
	s.muCurrentView.Lock()
	defer s.muCurrentView.Unlock()

	if curBlock == nil {
		curBlock = s.bc.CurrentBlock()
	}
	if curKeyBlock == nil {
		curKeyBlock = s.kbc.CurrentBlock()
	}

	s.currentView.TxNumber = curBlock.NumberU64()
	s.currentView.TxHash = curBlock.Hash()
	s.currentView.KeyNumber = curKeyBlock.NumberU64()
	s.currentView.KeyHash = curKeyBlock.Hash()
	s.currentView.CommitteeHash = curKeyBlock.CommitteeHash()

	if fromKeyBlock || curBlock.NumberU64() > curKeyBlock.T_Number() {
		s.currentView.LeaderIndex = 0
		s.currentView.NoDone = true
	}
	log.Debug("updateCurrentView", "TxNumber", s.currentView.TxNumber, "KeyNumber", s.currentView.KeyNumber, "LeaderIndex", s.currentView.LeaderIndex, "NoDone", s.currentView.NoDone)
	if fromKeyBlock || (s.currentView.TxNumber >= s.waittingView.TxNumber && s.currentView.KeyNumber >= s.waittingView.KeyNumber) || curBlock.BlockType() == types.Key_Block {
		s.sendNewViewMsg(s.currentView.TxNumber)
		s.waittingView.KeyNumber = s.currentView.KeyNumber
		s.waittingView.TxNumber = s.currentView.TxNumber
	}
}

func (s *Service) GetCurrentView() *bftview.View {
	s.muCurrentView.Lock()
	defer s.muCurrentView.Unlock()
	v := &s.currentView
	return v
}

func (s *Service) getBestCandidate(refresh bool) *types.Candidate {
	return s.keyService.getBestCandidate(refresh)
}

// Send new view when new block done
func (s *Service) sendNewViewMsg(curN uint64) {
	if bftview.IamMember() >= 0 && curN >= s.bc.CurrentBlockN() {
		s.hotstuffMsgQ.PushBack(&hotstuffMsg{sid: nil, lastN: curN, hMsg: &hotstuff.HotstuffMessage{Code: hotstuff.MsgStartNewView, Number: curN}})
	}
}

// Set next leader by prescribed rules
func (s *Service) setNextLeader(isDone bool) {
	s.muCurrentView.Lock()
	defer s.muCurrentView.Unlock()

	if isDone {
		s.currentView.LeaderIndex = s.keyService.getNextLeaderIndex(0)
	} else {
		s.currentView.LeaderIndex = s.keyService.getNextLeaderIndex(s.currentView.LeaderIndex)
	}
	s.currentView.NoDone = !isDone
	log.Info("setNextLeader", "isDone", isDone, "index", s.currentView.LeaderIndex)

	s.waittingView.TxNumber = s.currentView.TxNumber + 1
	s.waittingView.KeyNumber = s.currentView.KeyNumber + 1
}

func (s *Service) procBlockDone(block *types.Block) {
	var keyblock *types.KeyBlock
	beKeyBlock := false
	if block.BlockType() == types.Key_Block {
		keyblock = types.DecodeToKeyBlock(block.KeyInfo())
	}

	if keyblock != nil {
		beKeyBlock = true
		log.Info("@KeyBlockDone", "number", keyblock.NumberU64(), "T_number", keyblock.T_Number())
		s.updateCommittee(keyblock)
		s.saveCommittee(keyblock)
		s.updateCurrentView(block, keyblock, true)
		s.keyService.clearCandidate(keyblock)
	} else {
		log.Info("@TxBlockDone", "number", block.NumberU64(), "keyhash", block.KeyHash())
		s.updateCommittee(nil)
		s.updateCurrentView(block, keyblock, false)
		keyblock = s.kbc.CurrentBlock()
		//s.txPool.RemoveBatch(block.Transactions())
	}

	s.pacetMakerTimer.procBlockDone(block, keyblock, beKeyBlock)
	s.netService.procBlockDone(block.NumberU64(), keyblock.NumberU64())
	if keyblock != nil {
		s.kbc.PostBlock(keyblock)
	}
}

// call by miner.start
func (s *Service) start(config *common.NodeConfig) {
	if !s.isRunning() {
		s.protocolMng.UpdateKeyPair(bftview.StrToBlsPrivKey(config.Private))
		bftview.SetServerInfo(s.netService.serverAddress, config.Public)
		s.netService.StartStop(true)
		if bftview.IamMember() >= 0 {
			s.updateCommittee(nil)
			s.pacetMakerTimer.start()
		}
		s.updateCurrentView(nil, nil, false)
		s.setRunState(1)
	}
}

func (s *Service) stop() {
	if s.isRunning() {
		s.netService.StartStop(false)
		s.pacetMakerTimer.stop()
		s.setRunState(0)
	}
}

func (s *Service) isRunning() bool {
	//log all status
	//	if flag == 1 {
	//		go s.printAllStatus()
	//	}
	if s.kbc.CurrentBlock().NumberU64() == 131144 {
		keyblock := s.kbc.GetBlockByNumber(s.kbc.CurrentBlock().NumberU64())
		var mbNew = new(bftview.Committee)
		mbNew.List = []*common.Cnode{
			&common.Cnode{
				Address:  "61.29.244.73:7100",
				CoinBase: "0x83ea72f02b82199b29cae3118e163f3a05ef4b16",
				Public:   "139f38608c03b9a7799761afa93d1639735f561b3455f27be34018ad1455c90801d138c61b9f157c5f00b2dee0fc81256bfd9d413380963f77711b477696af04",
			},
			&common.Cnode{
				Address:  "61.29.244.66:7100",
				CoinBase: "0x999086e1149346e803535e7176e6ce8658883f33",
				Public:   "7993a80aa84986113d82708b3b2ec36f7b089da90489d8dea3aaf52fabee7a17205500ff3e0425d196729f0612a36a02c74a6763b17142feffda8d9181314d96",
			},
			&common.Cnode{
				Address:  "61.29.244.77:7100",
				CoinBase: "0x693ca592fa363109dc8b5e8a9a0c8d467d4e69a6",
				Public:   "a52b9830ca9f3cda0e7d78db4dd891b5dce05fb637164e5c68e73265ff6bd922c049cbb7f77fcde2dfd062881c486ff5b953aa02f883d234b8437e56df472da2",
			},
			&common.Cnode{
				Address:  "61.29.244.76:7100",
				CoinBase: "0x41fb9fdf1db61b4594e3ef0b27a6840f3d2e9208",
				Public:   "bf20503a2ab1f6d957e43c675bc2f25bc23739a7c388d23c2faedb32aa7c771e2380a1ed03cd2ebec6b09a402b7c3d1f61969926b79d91a52cc1cefbabf331a4",
			},
			&common.Cnode{
				Address:  "61.29.244.76:7100",
				CoinBase: "0x31cf88e26297545abdf1e6c1f8fb041cebb89290",
				Public:   "c0ac9fdb18faebfb9dc4d77731904acec5020e4fdd610d1e68a35b38e372cd0b883853f86b0a79e8ae0203f43a1107dbc7c0023ea3fb7b1abc15a3ce6896c586",
			},
			&common.Cnode{
				Address:  "61.29.244.13:7100",
				CoinBase: "0x630484e88ba61ba42f98f81bd5981e48b3547a58",
				Public:   "26ae6fbf46f2b75324631e55ff614c12726071e171d3c285ec4a27e33688b51ce5c24fcdbb09bc9f277546a210acad449f94b64a01cc5e577de9480b8272f49b",
			},
			&common.Cnode{
				Address:  "61.29.244.62:7100",
				CoinBase: "0xc3a86479301b07a5849e382418fd524fc9e88fbe",
				Public:   "ae633456e1e48a2c22a2d71cb7c708423f8881528672897a720e88992943091f7c8325f633e854e05ff07f9f6b7a66fadb95f17acfd0904b4a025753ce4a7412",
			},
			&common.Cnode{
				Address:  "61.29.244.65:7100",
				CoinBase: "0xca6df652714911b4c6d14881c143cc09e9ad61c0",
				Public:   "fafb82c0e658423ac0462d0895dd03b490ead2d148a281eb72ab101b6a58d60e97a718eb14f7a50e2b8a60884ce6c456ac27c16c58bfa7dcd9b006f34e463487",
			},
			&common.Cnode{
				Address:  "61.29.244.68:7100",
				CoinBase: "0x9ffedc42447cb915de3edf1593e81e95c06b408b",
				Public:   "ece5494aa77c14c699403871c3156b510e3ca0db08d625a189075503ec59001e6a6a359ac3d9232f96f21969f758262ec50b670a1d19827ec2f93fe4e017c502",
			},
			&common.Cnode{
				Address:  "61.29.244.60:7100",
				CoinBase: "0x737868db41e87d0dc7a694f7d401f016203e3d3b",
				Public:   "0ba57567572370db0722d2bb238a39605f6a3949b0fb660f2b36ad799cfdcd0e2d20a4cc1f111fdd1efda1af8b9d2136b108b617bc26e157465b34c46582cd8e",
			},
			&common.Cnode{
				Address:  "61.29.244.50:7100",
				CoinBase: "0xca0b3882b1e0a1540cfef7364ccf2ed8027fa86d",
				Public:   "d144b3e223a9a2868eb603446339c2d4372553d3451f10c7440c48e947e7fc1d2a4507a5ee46517f8b56a793dde13e8f6eeb7e49293c06fe66ca10d00c0a23a3",
			},
			&common.Cnode{
				Address:  "61.29.244.67:7100",
				CoinBase: "0x7cb40ba4a764d646100c5a9c058791b26ffbf96e",
				Public:   "2d8d22bb4a873f224d6a101a9fa24c614aea403ed5025e33c6da756a1507ea1c0ab37803475a23964b5f8649046f3a26c79863e2c567e6aedaffdac408438722",
			},
			&common.Cnode{
				Address:  "61.29.244.48:7100",
				CoinBase: "0x8c22b884c3f774dcd4f0cc4c6e920bd23b5d513f",
				Public:   "76c04ea4a0c0ee12a473b2d64a5e7c205d1837118619cfc811a1ee0cff929d1d50f6881c7af9e954aaadd3f0feea4c8d0405f454daeff79b9cee25fdbea6b51c",
			},
			&common.Cnode{
				Address:  "61.29.244.75:7100",
				CoinBase: "0x597fe78278722f5d96ba85bb66d67785015cbb8a",
				Public:   "5f715f77e352265d6b115fc36fe9b44700241c1300279e773f6ec2c8882a761e193785ce51a107ccf711eda85b7a51bb0a6fd6951520a67b8b0d6983c2b74e10",
			},
			&common.Cnode{
				Address:  "61.29.244.72:7100",
				CoinBase: "0x10ca2b7e3e26801e2a78c67000ac1982cb8b709e",
				Public:   "07223ea877650813afe8e5c1a4b7556931620fbbaed50db387b66c44b9d40e10652d18d6b8112d4f49b92fdf2195ac801a022c2ef0155418e7b0a01b8126f903",
			},
			&common.Cnode{
				Address:  "61.29.244.57:7100",
				CoinBase: "0x05c6aca0ab3e47c7515c93ea563dbaf8861d5d5f",
				Public:   "ee1b323335cba981e97e727bf718b3e160d0eae9f47af11ac4279dcce0067213040d9fca2ae842fb0cbc9c3f687414317d7589a2761014587b88c14f3cca1783",
			},
			&common.Cnode{
				Address:  "61.29.244.53:7100",
				CoinBase: "0xcab788f0767a3b62c33fe25ee3e87a94c0403f8e",
				Public:   "39fd9293185505b15c006c857fc39a148256edd998326fb998e7db224202f00769aae37d63287828c28181f0cb41dfcdd535d4e27f6c015592bd5a99fe4ef01e",
			},
			&common.Cnode{
				Address:  "61.29.244.48:7100",
				CoinBase: "0x52cd8c3a22a91b93b672f8d10e19d1c6fbe1ae42",
				Public:   "f2ea475b700ff366a21fdeb13d9701e9546270fe189cb52b7cdcd5a906d73e23fd0788af82e3f10be9f94ad076cc040ba4e37fc4f6c81746a54f4754d5354e18",
			},
			&common.Cnode{
				Address:  "61.29.244.63:7100",
				CoinBase: "0xaf006145afceb9b3f34c03b16893c98b72160323",
				Public:   "0fb677ab80eb75ec8f3eb15ec8697a80ef9a0cb4c4ad742b543b3b4f23ac8405df6b9526b0e0f2c601cb6c61d44a2d3f04a5838809adc85106ae78c19da7590c",
			},
			&common.Cnode{
				Address:  "61.29.244.57:7100",
				CoinBase: "0x5a3c2b79faa6cf64a33a701f345e96911112cbbd",
				Public:   "7b3b3d5f707068cd9ed515bba04dd732d8890ff2ba04c858ffec95e527874b10b1593686e3a8da9dd77bafbbd82830dd4c4108ef9c585d0356a3dacb3a47cd80",
			},
			&common.Cnode{
				Address:  "61.29.244.64:7100",
				CoinBase: "0x2d1e776d5ce8906dca30635819609b2bb2de245c",
				Public:   "e63d028382972a19d92fc19ed62bf71cd4585b09cf36577140cce80ce13f07018c21fabc109a83fa59e60d75dafc76aacfe7a5ef47960a7e04701d4cd64b12a3",
			},
		}
		mbNew.Store(keyblock)
	}
	return atomic.LoadInt32(&s.runningState) == 1
}

func (s *Service) printAllStatus() {
	s.netService.GetNetBlocks(nil)
	for addr, a := range s.netService.ackMap {
		si := network.NewServerIdentity(addr)
		log.Info("ackInfo", "addr", addr, "id", si.ID)
		if a != nil {
			log.Info("ackInfo", "ackTm", a.ackTm, "sendTm", a.sendTm, "isSending", *a.isSending)
		}
	}
}

func (s *Service) setRunState(state int32) {
	atomic.StoreInt32(&s.runningState, state)
}

func (s *Service) LeaderAckTime() time.Time {
	mb := bftview.GetCurrentMember()
	if mb != nil {
		curView := s.GetCurrentView()
		leader := mb.List[curView.LeaderIndex]
		return s.netService.GetAckTime(leader.Address)
	}
	return time.Now()
}

func (s *Service) ResetLeaderAckTime() {
	mb := bftview.GetCurrentMember()
	if mb != nil {
		curView := s.GetCurrentView()
		leader := mb.List[curView.LeaderIndex]
		s.netService.ResetAckTime(leader.Address)
	}
}

func (s *Service) Exceptions(blockNumber int64) []string {
	block := s.bc.GetBlockByNumber(uint64(blockNumber))
	if block == nil {
		return nil
	}
	cm := s.kbc.GetCommitteeByHash(block.KeyHash())
	if cm == nil {
		return nil
	}
	indexs := hotstuff.MaskToExceptionIndexs(block.SignInfo().Exceptions, len(cm))
	if indexs == nil {
		return nil
	}
	var exs []string
	for _, i := range indexs {
		exs = append(exs, cm[i].CoinBase)
	}
	return exs
}

func (s *Service) TakePartInBlocks(address common.Address, checkKeyNumber int64) []string {
	coinbase := strings.ToLower(address.String())
	coinbase = coinbase[2:] //del 0x
	if checkKeyNumber < 0 || uint64(checkKeyNumber) > s.kbc.CurrentBlockN() {
		return nil
	}

	keyNumber := uint64(checkKeyNumber)
	keyblock := s.kbc.GetBlockByNumber(keyNumber)
	if keyblock == nil {
		return nil
	}
	c := bftview.LoadMember(keyNumber, keyblock.Hash(), false)
	if c == nil {
		return nil
	}
	isMember := false
	memberI := 0
	for i, r := range c.List {
		ss := strings.ToLower(r.CoinBase)
		if strings.HasPrefix(ss, "0x") {
			ss = ss[2:]
		}
		if ss == coinbase {
			isMember = true
			memberI = i
			break
		}
	}
	if !isMember {
		return nil
	}
	var takePartInNumberList []string

	fromN := keyblock.T_Number() + 1
	toN := uint64(0)
	if keyNumber == s.kbc.CurrentBlockN() {
		toN = s.bc.CurrentBlockN()
	} else {
		nextkeyblock := s.kbc.GetBlockByNumber(keyNumber + 1)
		toN = nextkeyblock.T_Number()
	}
	if toN < fromN {
		return nil
	}
	n := len(c.List)
	for i := fromN; i <= toN; i++ {
		block := s.bc.GetBlockByNumber(i)
		if block == nil {
			return nil
		}
		indexs := hotstuff.MaskToExceptionIndexs(block.SignInfo().Exceptions, n)
		if indexs == nil {
			takePartInNumberList = append(takePartInNumberList, strconv.FormatInt(int64(i), 10))
			continue
		}
		isException := false
		for _, j := range indexs {
			if j == memberI {
				isException = true
				break
			}
		}
		if !isException {
			takePartInNumberList = append(takePartInNumberList, strconv.FormatInt(int64(i), 10))
		}
	}

	return takePartInNumberList
}

func (s *Service) SwitchOK() bool {
	fromN := int(s.kbc.CurrentBlockN() - uint64(bftview.GetServerCommitteeLen()/3+1))
	if fromN <= 0 {
		return true
	}
	keyblock := s.kbc.GetBlockByNumber(uint64(fromN))
	if s.bc.CurrentBlockN()-keyblock.T_Number() > 0 {
		return true
	}
	return false
}
