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
	"sync"
	"sync/atomic"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/math"
	"github.com/cypherium/cypher/core"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rlp"
	"github.com/cypherium/cypher/rnet"
	"github.com/cypherium/cypher/rnet/network"
	"golang.org/x/crypto/sha3"
)

type serviceCallback interface {
	networkMsgAck(si *network.ServerIdentity, msg *networkMsg)
}

const Gossip_MSG = 8

type heartBeatMsg struct {
	BlockN uint64
}
type checkMinerMsg struct {
	BlockN    uint64
	KeyblockN uint64
	AckFlag   uint64
}

type ackInfo struct {
	ackTm     time.Time
	sendTm    time.Time
	isSending *int32 //atomic int
}

type msgHeadInfo struct {
	blockN    uint64
	keyblockN uint64
}

type netService struct {
	*rnet.ServiceProcessor // We need to embed the ServiceProcessor, so that incoming messages are correctly handled.
	server                 *rnet.Server
	serverAddress          string
	serverID               string
	gossipMsg              map[common.Hash]*msgHeadInfo
	muGossip               sync.Mutex

	goMap     map[string]*int32 //atomic int
	idDataMap map[string]*common.Queue
	ackMap    map[string]*ackInfo
	muIdMap   sync.Mutex

	backend       serviceCallback
	curBlockN     uint64
	curKeyBlockN  uint64
	isStoping     bool
	candidatepool *core.CandidatePool
	bc            *core.BlockChain
	kbc           *core.KeyBlockChain
}

func newNetService(sName, sIp string, chainConfig *params.ChainConfig, backend *ReconfigBackend, callback serviceCallback) *netService {
	registerService := func(c *rnet.Context) (rnet.Service, error) {
		s := &netService{ServiceProcessor: rnet.NewServiceProcessor(c)}
		s.RegisterProcessorFunc(network.RegisterMessage(&networkMsg{}), s.handleNetworkMsgAck)
		s.RegisterProcessorFunc(network.RegisterMessage(&heartBeatMsg{}), s.handleHeartBeatMsgAck)
		s.RegisterProcessorFunc(network.RegisterMessage(&checkMinerMsg{}), s.handleCheckMinerMsgAck)

		return s, nil
	}
	rnet.RegisterNewService(sName, registerService)
	server := rnet.NewKcpServer(sIp)
	s := server.Service(sName).(*netService)
	s.server = server
	s.serverID = sIp
	s.serverAddress = sIp

	s.gossipMsg = make(map[common.Hash]*msgHeadInfo)
	s.goMap = make(map[string]*int32)
	s.idDataMap = make(map[string]*common.Queue)
	s.ackMap = make(map[string]*ackInfo)
	s.backend = callback
	s.candidatepool = backend.CandidatePool()
	s.bc = backend.BlockChain()
	s.kbc = backend.KeyBlockChain()

	return s
}

func (s *netService) StartStop(isStart bool) {
	if isStart {
		s.server.Start()
		go s.heartBeat_Loop()
	} else { //stop
		s.isStoping = true
		//..............................
	}
}

//----------------------------------------------------------------------------------------------------
func (s *netService) CheckMinerPort(addr string, blockN uint64, keyblockN uint64, ackFlag uint64) {
	msg := &checkMinerMsg{BlockN: blockN, KeyblockN: keyblockN, AckFlag: ackFlag}
	log.Info("CheckMinerPort", "addr", addr, "msg", msg)
	si := network.NewServerIdentity(addr)
	go s.SendRaw(si, msg, true)
}

func (s *netService) handleCheckMinerMsgAck(env *network.Envelope) {
	msg, ok := env.Msg.(*checkMinerMsg)
	if !ok {
		log.Error("handleCheckMinerMsgAck failed to cast to ")
		return
	}
	si := env.ServerIdentity
	address := si.Address.String()
	log.Debug("handleCheckMinerMsgAck Recv", "from address", address, "blockN", msg.BlockN, "keyblockN", msg.KeyblockN, "ackFlag", msg.AckFlag)
	if msg.AckFlag == 111 {
		s.CheckMinerPort(address, s.bc.CurrentBlockN(), s.kbc.CurrentBlockN(), 0)
	} else {
		s.candidatepool.CheckMinerMsgAck(address, msg.BlockN, msg.KeyblockN)
	}
}

//----------------------------------------------------------------------------------------------------
func (s *netService) AdjustConnect(outAddress string) {
	s.setIsRunning(outAddress, false)
}

func (s *netService) procBlockDone(blockN, keyblockN uint64) {

	atomic.StoreUint64(&s.curBlockN, blockN)
	atomic.StoreUint64(&s.curKeyBlockN, keyblockN)

	//clear old cache of gossipMsg
	s.muGossip.Lock()
	for k, h := range s.gossipMsg {
		if (h.blockN > 0 && h.blockN < blockN) || (h.keyblockN > 0 && h.keyblockN < keyblockN) {
			delete(s.gossipMsg, k)
		}
	}
	s.muGossip.Unlock()
	s.ResetAckTime("")
}

func (s *netService) handleNetworkMsgAck(env *network.Envelope) {
	msg, ok := env.Msg.(*networkMsg)
	if !ok {
		log.Error("handleNetworkMsgReq failed to cast to ")
		return
	}
	if msg.Cmsg == nil && msg.Bmsg == nil && msg.Hmsg == nil {
		log.Error("handleNetworkMsgReq nil message")
		return
	}
	si := env.ServerIdentity
	address := si.Address.String()
	//	log.Info("handleNetworkMsgReq Recv", "from address", address)
	s.getAckInfo(address).ackTm = time.Now()

	if s.IgnoreMsg(msg) {
		return
	}

	if (msg.MsgFlag & Gossip_MSG) > 0 {
		hash := rlpHash(msg)
		s.muGossip.Lock()
		m, ok := s.gossipMsg[hash]
		s.muGossip.Unlock()
		if !ok {
			s.broadcast(address, msg)
		} else {
			log.Info("Gossip_MSG Recv Same", "hash", hash, "keyblockN", m.keyblockN, "blockN", m.blockN)
			return
		}
	}
	s.backend.networkMsgAck(si, msg)
}

func (s *netService) broadcast(fromAddr string, msg *networkMsg) {
	mb := msg.GetCommittee()
	if mb == nil {
		log.Error("broadcast", "error", "can't find current committee")
		return
	}
	if fromAddr != "" {
		p, _ := mb.Get(fromAddr, bftview.Address)
		if p == nil {
			log.Error("broadcast", "can't find current committee address", fromAddr)
			return
		}
	}
	msg.MsgFlag = Gossip_MSG
	hash := rlpHash(msg)
	hInfo := s.getMsgHeadInfo(msg)
	log.Info("Gossip_MSG broadcast", "hash", hash, "keyblockN", hInfo.keyblockN, "blockN", hInfo.blockN)

	s.muGossip.Lock()
	s.gossipMsg[hash] = hInfo
	s.muGossip.Unlock()

	mblist := mb.List
	n := len(mblist)
	seedIndexs := math.GetRandIntArray(n, n/2+3)
	for i, _ := range seedIndexs {
		if mblist[i].Address == "" {
			continue
		}
		if IsSelf(mblist[i].Address) {
			continue
		}
		s.SendRawData(mblist[i].Address, msg)
	}
}

func (s *netService) SendRawData(address string, msg *networkMsg) error {
	//	log.Info("SendRawData", "to address", address)
	if address == s.serverAddress {
		return nil
	}

	s.setIsRunning(address, true)
	s.muIdMap.Lock()
	q, ok := s.idDataMap[address]
	s.muIdMap.Unlock()
	if ok && q != nil {
		q.PushBack(msg)
	}
	//	log.Info("SendRawData", "to address", address, "msg", msg)
	return nil
}

func (s *netService) loop_iddata(address string, q *common.Queue) {
	log.Debug("loop_iddata start", "address", address)
	si := network.NewServerIdentity(address)

	s.muIdMap.Lock()
	isRunning, _ := s.goMap[address]
	s.muIdMap.Unlock()

	for !s.isStoping && atomic.LoadInt32(isRunning) == 1 {
		if s.GetNetBlocks(si) > 1 {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		msg := q.PopFront()
		if msg != nil {
			m, ok := msg.(*networkMsg)
			if ok && s.IgnoreMsg(m) {
				continue
			}
			err := s.SendRaw(si, msg, false)
			if err != nil {
				//if err == SendOverFlowErr {}
				log.Warn("SendRawData", "couldn't send to", address, "error", err)
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	atomic.StoreInt32(isRunning, 0)

	s.muIdMap.Lock()
	delete(s.goMap, address)
	delete(s.idDataMap, address)
	delete(s.ackMap, address)
	s.muIdMap.Unlock()

	log.Debug("loop_iddata exit", "id", address)
}

func (s *netService) getMsgHeadInfo(msg *networkMsg) *msgHeadInfo {
	hInfo := new(msgHeadInfo)
	if msg.Cmsg != nil {
		hInfo.keyblockN = msg.Cmsg.KeyNumber
		hInfo.blockN = 0
	} else if msg.Bmsg != nil {
		hInfo.keyblockN = msg.Bmsg.KeyNumber
		hInfo.blockN = 0
	} else if msg.Hmsg != nil {
		hInfo.keyblockN = 0
		hInfo.blockN = msg.Hmsg.Number
	}
	return hInfo
}

func (s *netService) IgnoreMsg(m *networkMsg) bool {
	if m.Cmsg != nil {
		if m.Cmsg.KeyNumber < atomic.LoadUint64(&s.curKeyBlockN) {
			return true
		}
	} else if m.Bmsg != nil {
		if m.Bmsg.KeyNumber < atomic.LoadUint64(&s.curKeyBlockN) {
			return true
		}
	} else if m.Hmsg != nil {
		if m.Hmsg.Number < atomic.LoadUint64(&s.curBlockN) {
			return true
		}
	}
	return false
}

//------------------------------------------------------------------------------------------
func (s *netService) isRunning(id string) int32 {
	s.muIdMap.Lock()
	isRunning, ok := s.goMap[id]
	s.muIdMap.Unlock()
	if ok {
		return atomic.LoadInt32(isRunning)
	}
	return 0
}

func (s *netService) setIsRunning(id string, isStart bool) {
	s.muIdMap.Lock()
	isRunning, ok := s.goMap[id]
	if !ok {
		if isStart == false {
			s.muIdMap.Unlock()
			return
		}
		isRunning = new(int32)
		s.goMap[id] = isRunning
	}
	s.muIdMap.Unlock()
	i := atomic.LoadInt32(isRunning)
	if isStart {
		atomic.StoreInt32(isRunning, 1)
		if i == 0 {
			s.muIdMap.Lock()
			q, ok := s.idDataMap[id]
			if !ok {
				q = common.QueueNew()
				s.idDataMap[id] = q
			}
			s.muIdMap.Unlock()
			go s.loop_iddata(id, q)
		}
	} else {
		if i == 1 {
			atomic.StoreInt32(isRunning, 2)
		}
	}
}

//-------------------------------------------------------------------------------------------------------------------------------------------
func (s *netService) handleHeartBeatMsgAck(env *network.Envelope) {
	_, ok := env.Msg.(*heartBeatMsg)
	if !ok {
		log.Error("handleNetworkMsgReq failed to cast to ")
		return
	}
	si := env.ServerIdentity
	address := si.Address.String()
	//log.Info("handleHeartBeatMsgAck Recv", "from address", address, "blockN", msg.blockN)
	s.getAckInfo(address).ackTm = time.Now()
}

func (s *netService) getAckInfo(addr string) *ackInfo {
	s.muIdMap.Lock()
	a := s.ackMap[addr]
	if a == nil {
		a = new(ackInfo)
		a.isSending = new(int32)
		a.ackTm = time.Now()
		s.ackMap[addr] = a
	}
	s.muIdMap.Unlock()
	return a
}

func (s *netService) heartBeat_Loop() {
	heatBeatTimeout := params.HeatBeatTimeout
	for !s.isStoping {
		mb := bftview.GetCurrentMember()
		if mb == nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		now := time.Now()
		msg := &heartBeatMsg{BlockN: atomic.LoadUint64(&s.curBlockN)}
		for _, node := range mb.List {
			if IsSelf(node.Address) {
				continue
			}
			addr := node.Address
			a := s.getAckInfo(addr)
			if a != nil && now.Sub(a.sendTm) > heatBeatTimeout {
				if atomic.LoadInt32(a.isSending) == 0 {
					si := network.NewServerIdentity(addr)
					if s.GetNetBlocks(si) == 0 {
						a.sendTm = time.Now()
						go func(si *network.ServerIdentity, msg interface{}, isRunning *int32) {
							atomic.StoreInt32(isRunning, 1)
							s.SendRaw(si, msg, false)
							//log.Debug("sendHeartBeatMsg", "address", si.Address, "tm", time.Now(), "error", err)
							atomic.StoreInt32(isRunning, 0)
						}(si, msg, a.isSending)
					}
				}
				continue
			}
		}
		time.Sleep(500 * time.Millisecond)
	} //end for  !s.isStoping
}

func (s *netService) GetAckTime(addr string) time.Time {
	return s.getAckInfo(addr).ackTm
}

func (s *netService) ResetAckTime(addr string) {
	now := time.Now()

	s.muIdMap.Lock()
	if addr != "" {
		a, ok := s.ackMap[addr]
		if ok {
			a.ackTm = now
		}
	} else {
		for _, a := range s.ackMap {
			a.ackTm = now
		}
	}
	s.muIdMap.Unlock()
}

//--------------------------------------------------------------------------------------------------------------------------
func rlpHash(x interface{}) (h common.Hash) {
	hw := sha3.NewLegacyKeccak256()
	rlp.Encode(hw, x)
	hw.Sum(h[:0])
	return h
}

func IsSelf(addr string) bool {
	return addr == bftview.GetServerAddress()
}
