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

// Package bftview implements Cypherium committee common operation functions.
package bftview

import (
	"bytes"
	"encoding/hex"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/rlp"
	"golang.org/x/crypto/sha3"
)

type ServerInfo struct {
	address  string
	pubKey   string
	coinbase common.Address
}
type KeyBlockChainInterface interface {
	CurrentBlock() *types.KeyBlock
	CurrentBlockN() uint64
	GetBlockByHash(hash common.Hash) *types.KeyBlock
	CurrentCommittee() []*common.Cnode
}
type ServiceInterface interface {
	Committee_OnStored(*types.KeyBlock)
	Committee_Request(kNumber uint64, hash common.Hash)
}

//type Committee []*common.Cnode
type Committee struct {
	List []*common.Cnode
}

type currentMemberInfo struct {
	kNumber uint64
	hash    common.Hash
	mIndex  int
}

type ServerInfoType int

const (
	PublicKey ServerInfoType = iota
	PrivateKey
	Address
	ID
)

type committeeCache struct {
	committee *Committee
	hasIP     bool
	number    uint64
	pubs      []*bls.PublicKey
}

type CommitteeConfig struct {
	db               ethdb.Database
	keyblockchain    KeyBlockChainInterface
	service          ServiceInterface
	serverInfo       ServerInfo
	cacheCommittee   map[common.Hash]*committeeCache
	muCommitteeCache sync.Mutex
	currentMember    atomic.Value
	commiteeLen      int
	maxKeyNumber     uint64
}

const CommitteeCacheSize = 10

var m_config CommitteeConfig

func SetCommitteeConfig(db ethdb.Database, keyblockchain KeyBlockChainInterface, service ServiceInterface) {
	m_config.db = db
	m_config.keyblockchain = keyblockchain
	m_config.service = service

	m_config.cacheCommittee = make(map[common.Hash]*committeeCache)
	m_config.currentMember.Store(&currentMemberInfo{kNumber: 1<<63 - 1, mIndex: -1})
	if keyblockchain != nil {
		c := keyblockchain.CurrentCommittee()
		if c != nil {
			m_config.commiteeLen = len(c)
		}
	}
	log.Info("SetCommitteeConfig", "len", m_config.commiteeLen)
}

func SetServerInfo(address, pubKey string) {
	m_config.serverInfo.address = address
	m_config.serverInfo.pubKey = pubKey
}

func GetServerCommitteeLen() int {
	return m_config.commiteeLen
}
func GetServerAddress() string {
	return m_config.serverInfo.address
}
func GetServerCoinBase() common.Address {
	return m_config.serverInfo.coinbase
}

func GetServerInfo(infoType ServerInfoType) string {
	s := m_config.serverInfo
	switch infoType {
	case PublicKey:
		return s.pubKey
	//	case PrivateKey:
	//		return s.private
	case Address:
		return string(s.address)
	case ID:
		return GetNodeID(string(s.address), s.pubKey)
	}
	return ""
}

// load committee by keyblock number, needIP is for ignore ip address
func LoadMember(kNumber uint64, hash common.Hash, needIP bool) *Committee {
	m_config.muCommitteeCache.Lock()
	c, ok := m_config.cacheCommittee[hash]
	m_config.muCommitteeCache.Unlock()
	if ok {
		if !needIP || c.hasIP {
			return c.committee
		}
	}

	cm := ReadCommittee(kNumber, hash)
	if cm != nil && cm.List != nil && len(cm.List) >= 0 {
		hasIP := cm.HasIP()
		cm.storeInCache(hash, kNumber, hasIP)
		if !needIP || hasIP {
			return cm
		}
	}
	return nil
}

// Store committee in cache
func (committee *Committee) storeInCache(hash common.Hash, keyNumber uint64, hasIP bool) {
	m_config.muCommitteeCache.Lock()
	defer m_config.muCommitteeCache.Unlock()

	if keyNumber > m_config.maxKeyNumber {
		m_config.maxKeyNumber = keyNumber
	}

	maxN := m_config.maxKeyNumber
	for h, v := range m_config.cacheCommittee {
		if v.number < maxN-CommitteeCacheSize {
			delete(m_config.cacheCommittee, h)
		}
	}

	m_config.cacheCommittee[hash] = &committeeCache{number: keyNumber, committee: committee, hasIP: hasIP}
}

func DeleteMember(kNumber uint64, hash common.Hash) {
	committee := LoadMember(kNumber, hash, false)
	if committee != nil {
		DeleteCommittee(kNumber, hash)
	}
}

func GetCurrentMember() *Committee {
	if m_config.keyblockchain == nil {
		log.Error("Committee.GetCurrent", "keyblockchain is nil", "")
		return nil
	}
	curBlock := m_config.keyblockchain.CurrentBlock()
	c := LoadMember(curBlock.NumberU64(), curBlock.Hash(), true)
	if c == nil {
		//log.Error("Committee.GetCurrent", "Roster or list is nil, keyblock number", curBlock.NumberU64())
		return nil
	}
	return c
}

func IamLeader(leaderIndex uint) bool {
	myPubKey := GetServerInfo(PublicKey)
	if myPubKey == "" {
		return false
	}
	committee := GetCurrentMember()
	if committee == nil {
		return false
	}

	sLeader := committee.List[leaderIndex].Public
	if sLeader == myPubKey {
		return true
	}
	return false
}

// return the member's index in current committee
func IamMember() int {
	myPubKey := GetServerInfo(PublicKey)
	if myPubKey == "" {
		return -1
	}
	if m_config.keyblockchain == nil {
		log.Error("Committee.IamMember", "keyblockchain is nil", "")
		return -1
	}
	kNumber := m_config.keyblockchain.CurrentBlockN()
	m := m_config.currentMember.Load().(*currentMemberInfo)
	if m != nil && m.kNumber == kNumber {
		if m_config.keyblockchain.CurrentBlock().Hash() == m.hash {
			return m.mIndex
		}
	}
	list := m_config.keyblockchain.CurrentCommittee()
	for i, r := range list {
		if r.Public == myPubKey {
			m_config.currentMember.Store(&currentMemberInfo{kNumber: kNumber, hash: m_config.keyblockchain.CurrentBlock().Hash(), mIndex: i})
			return i
		}
	}
	return -1
}

func IamMemberByNumber(kNumber uint64, hash common.Hash) bool {
	c := LoadMember(kNumber, hash, false)
	if c == nil {
		return false
	}
	myPubKey := GetServerInfo(PublicKey)
	for _, r := range c.List {
		if r.Public == myPubKey {
			return true
		}
	}
	return false
}

func GetMemberIndex(pubKey string) int { //==0 is leader
	committee := GetCurrentMember()
	if committee == nil {
		return -1
	}

	p, i := committee.Get(pubKey, PublicKey)
	if p != nil {
		return i
	}
	return -1
}

func (committee *Committee) Get(key string, findType ServerInfoType) (*common.Cnode, int) {
	for i, r := range committee.List {
		switch findType {
		case PublicKey:
			if r.Public == key {
				return r, i
			}
		case Address:
			if r.Address == key {
				return r, i
			}
		case ID:
			if GetNodeID(r.Address, r.Public) == key {
				return r, i
			}
		}
	}
	return nil, -1
}

func (committee *Committee) Store(keyblock *types.KeyBlock) bool {
	if committee.RlpHash() != keyblock.CommitteeHash() {
		log.Error("Committee.Store", "committee.RlpHash != keyblock.CommitteeHash keyblock number", keyblock.NumberU64())
		return false
	}

	ok := WriteCommittee(keyblock.NumberU64(), keyblock.Hash(), committee)
	if ok && m_config.service != nil {
		m_config.service.Committee_OnStored(keyblock)
	}
	return ok
}

func (committee *Committee) Store0(keyblock *types.KeyBlock) bool {
	if committee.RlpHash() != keyblock.CommitteeHash() {
		log.Error("Committee.Store", "committee.RlpHash != keyblock.CommitteeHash keyblock number", keyblock.NumberU64())
		return false
	}
	ok := WriteCommittee(keyblock.NumberU64(), keyblock.Hash(), committee)
	return ok
}

func (committee *Committee) Copy() *Committee {
	p := &Committee{}
	p.List = make([]*common.Cnode, len(committee.List))
	for i, r := range committee.List {
		p.List[i] = r
	}
	return p
}

// Add member node to committee, one in and one out
func (committee *Committee) Add(r *common.Cnode, leaderIndex int, outAddress string) *common.Cnode {
	n := len(committee.List)
	leader := committee.List[leaderIndex]
	list0 := committee.List[0]
	if r != nil { //pow
		for i := 0; i < n; i++ {
			if committee.List[i].Public == r.Public {
				return nil
			}
		}
		if outAddress != "" && outAddress[0] == '*' {
			outAddress = outAddress[1:]
		}
		outAddrI := 0
		isIp := strings.Contains(outAddress, ".")
		var outer *common.Cnode
		if leaderIndex > 0 {
			for i := leaderIndex; i < n-1; i++ {
				committee.List[i] = committee.List[i+1]
				if outAddress != "" && outAddrI == 0 && ((isIp && committee.List[i].Address == outAddress) || (!isIp && committee.List[i].CoinBase == outAddress)) {
					outAddrI = i
				}
			}
			//log.Info("committee.Add", "outAddrI", outAddrI, "leaderIndex", leaderIndex)
			outer = committee.List[leaderIndex-1]
			committee.List[leaderIndex-1] = list0
			if leaderIndex-1 == 0 && outAddrI > 0 && leaderIndex != outAddrI {
				outer = committee.List[outAddrI]
				committee.List[outAddrI] = list0
			}
		} else {
			outer = committee.List[n-1]
		}

		committee.List[0] = leader
		committee.List[n-1] = r
		return outer
	} else { //change leader
		if leaderIndex > 0 {
			for i := leaderIndex; i < n-1; i++ {
				committee.List[i] = committee.List[i+1]
			}
			bader := committee.List[leaderIndex-1]
			committee.List[leaderIndex-1] = list0
			committee.List[0] = leader
			committee.List[n-1] = bader
		}
		return nil
	}
	return nil
}

func (committee *Committee) RlpHash() (h common.Hash) {
	type committeeEx struct {
		CoinBase []string
		Public   []string
	}
	n := len(committee.List)
	p := &committeeEx{}
	p.CoinBase = make([]string, n)
	p.Public = make([]string, n)
	for i, r := range committee.List {
		p.CoinBase[i] = r.CoinBase
		p.Public[i] = r.Public
	}
	hw := sha3.NewLegacyKeccak256()
	rlp.Encode(hw, p)
	hw.Sum(h[:0])
	return h
}
func (committee *Committee) Leader() *common.Cnode {
	return committee.List[0]
}
func (committee *Committee) In() *common.Cnode {
	return committee.List[len(committee.List)-1]
}

// Convert committee's public key to bls public key
func (committee *Committee) ToBlsPublicKeys(hash common.Hash) []*bls.PublicKey {
	m_config.muCommitteeCache.Lock()
	c, ok := m_config.cacheCommittee[hash]
	m_config.muCommitteeCache.Unlock()
	if ok && c.pubs != nil {
		//log.Info("ToBlsPublicKeys found in cache")
		return c.pubs
	}

	pubs := make([]*bls.PublicKey, 0)
	for _, r := range committee.List {
		pubs = append(pubs, StrToBlsPubKey(r.Public))
	}

	if ok {
		m_config.muCommitteeCache.Lock()
		c.pubs = pubs
		m_config.muCommitteeCache.Unlock()
	}

	return pubs
}
func (committee *Committee) HasIP() bool {
	list := committee.List
	n := len(list)
	for i := n - 1; i >= 0; i-- {
		if list[i].Address == "" {
			return false
		}
	}
	/*
		if list[0].Address) == "" { //for quickly check
			return false
		}
		if list[n-1].Address == "" {
			return false
		}
	*/
	return true
}

//------Tools---------------------------------------------------------------------------------------------------------
func ToBlsPublicKeys(hash common.Hash) []*bls.PublicKey {
	m_config.muCommitteeCache.Lock()
	c, ok := m_config.cacheCommittee[hash]
	m_config.muCommitteeCache.Unlock()
	if ok && c.pubs != nil {
		//log.Info("ToBlsPublicKeys found in cache")
		return c.pubs
	}
	return nil
}

func GetCommittee(newNode *common.Cnode, keyblock *types.KeyBlock, needIp bool) (mb *Committee, outer *common.Cnode) {
	if m_config.keyblockchain == nil {
		log.Error("GetCommittee", "keyblockchain is nil", "")
		return nil, nil
	}
	parentKeyBlock := m_config.keyblockchain.GetBlockByHash(keyblock.ParentHash())
	parentMb := LoadMember(parentKeyBlock.NumberU64(), parentKeyBlock.Hash(), needIp)
	if parentMb == nil {
		//log.Error("GetCommittee", "parent Roster or list is nil keyNumber", parentKeyBlock.NumberU64())
		return nil, nil
	}

	_, index := parentMb.Get(keyblock.LeaderPubKey(), PublicKey)
	if index < 0 {
		log.Error("GetCommittee", "can't found the leader publickey", keyblock.LeaderPubKey())
		return nil, nil
	}
	if keyblock.HasNewNode() {
		if newNode == nil {
			log.Error("GetCommittee", "PowReconfig or PacePowReconfig should have new node", "")
			return nil, nil
		}
		mb = parentMb.Copy()
		outer = mb.Add(newNode, int(index), keyblock.OutAddress(1))
	} else {
		mb = parentMb.Copy()
		outer = mb.Add(nil, int(index), keyblock.OutAddress(1))
	}
	return mb, outer
}

func GetNodeID(addr string, pub string) string {
	return addr // + pub[len(pub)-10:]
}

func StrToBlsPubKey(s string) *bls.PublicKey {
	h, _ := hex.DecodeString(s)
	return bls.GetPublicKey(h)
	//p := new(bls.PublicKey)
	//p.DeserializeHexStr(s)
	//return p
}
func StrToBlsPrivKey(s string) *bls.SecretKey {
	p := new(bls.SecretKey)
	p.DeserializeHexStr(s)
	return p
}

// ReadCommittee retrieves the committee.
func ReadCommitteeFromDB(db ethdb.Database, number uint64, hash common.Hash) *Committee {
	if db == nil {
		log.Error("ReadCommitteeFromDB", "db is nil", "")
		return nil
	}
	data, _ := db.Get(rawdb.CommitteeKey(number, hash))
	if len(data) == 0 {
		log.Warn("ReadCommitteeFromDB", "read data is empty", "")
		return nil
	}
	cm := new(Committee)
	if err := rlp.Decode(bytes.NewReader(data), cm); err != nil {
		log.Error("Invalid Committee RLP", "hash", hash, "err", err)
		return nil
	}
	return cm
}

func ReadCommittee(number uint64, hash common.Hash) *Committee {
	return ReadCommitteeFromDB(m_config.db, number, hash)
}

func WriteCommittee(keyBlockNumber uint64, hash common.Hash, cm *Committee) bool {
	if m_config.db == nil {
		log.Error("WriteCommittee", "db is nil", "")
		return false
	}
	if cm == nil {
		log.Warn("WriteCommittee:Try to store nil committee.")
		return false
	}

	data, err := rlp.EncodeToBytes(cm)
	if err != nil {
		log.Error("Failed to RLP encode Committee", "err", err)
		return false
	}
	//	log.Info("@@", "number", keyBlockNumber, "hash", hash)
	key := rawdb.CommitteeKey(keyBlockNumber, hash)
	if err := m_config.db.Put(key, data); err != nil {
		log.Error("Failed to store header", "err", err)
		return false
	}
	return true
}

func DeleteCommittee(keyBlockNumber uint64, hash common.Hash) {
	if m_config.db == nil {
		log.Error("WriteCommittee", "db is nil", "")
		return
	}
	if err := m_config.db.Delete(rawdb.CommitteeKey(keyBlockNumber, hash)); err != nil {
		log.Crit("Failed to delete committee", "err", err)
	}
}
