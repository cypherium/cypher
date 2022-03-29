package hotstuff

import (
	"encoding/hex"
	"fmt"
	"time"

	"bytes"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/crypto/bls"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
)

var (
	ErrNewViewFail            = fmt.Errorf("hotstuff new view fail")
	ErrUnhandledMsg           = fmt.Errorf("hotstuff unhandled message")
	ErrViewTimeout            = fmt.Errorf("hotstuff view timeout")
	ErrQCVerification         = fmt.Errorf("hotstuff QC not valid")
	ErrInvalidReplica         = fmt.Errorf("hotstuff replica not valid")
	ErrInvalidVoteInfoMessage = fmt.Errorf("hotstuff voteInfo message not valid")
	ErrInsufficientQC         = fmt.Errorf("hotstuff QC insufficient")
	ErrInvalidHighQC          = fmt.Errorf("hotstuff highQC invalid")
	ErrInvalidPrepareQC       = fmt.Errorf("hotstuff prepareQC invalid")
	ErrInvalidPreCommitQC     = fmt.Errorf("hotstuff preCommitQC invalid")
	ErrInvalidCommitQC        = fmt.Errorf("hotstuff commitQC invalid")
	ErrInvalidProposal        = fmt.Errorf("hotstuff proposal invalid")
	ErrInvalidPublicKey       = fmt.Errorf("invalid public key for bls deserialize")
	ErrViewPhaseNotMatch      = fmt.Errorf("hotstuff view phase not match")
	ErrViewOldPhase           = fmt.Errorf("hotstuff old phase ")

	ErrMissingView       = fmt.Errorf("hotstuff view missing")
	ErrInvalidLeaderView = fmt.Errorf("hotstuff invalid leader view")
	ErrExistingView      = fmt.Errorf("hotstuff view existing")
	ErrViewIdNotMatch    = fmt.Errorf("hotstuff view id not match")

	ErrOldState    = fmt.Errorf("hotstuff view state too old")
	ErrFutureState = fmt.Errorf("hotstuff view state of future")
)

const (
	MsgNewView = iota
	MsgPrepare
	MsgVotePrepare
	MsgPreCommit
	MsgVotePreCommit
	MsgCommit
	MsgVoteCommit
	MsgDecide

	// pseudo messages
	MsgStartNewView // for handling new view from app
	MsgTryPropose
	MsgTimer
)

func ReadableMsgType(m uint32) string {
	switch {
	case m == MsgNewView:
		return "MsgNewView"
	case m == MsgPrepare:
		return "MsgPrepare"
	case m == MsgVotePrepare:
		return "MsgVotePrepare"
	case m == MsgPreCommit:
		return "MsgPreCommit"
	case m == MsgVotePreCommit:
		return "MsgVotePreCommit"
	case m == MsgCommit:
		return "MsgCommit"
	case m == MsgVoteCommit:
		return "MsgVoteCommit"
	case m == MsgDecide:
		return "MsgDecide"
	case m == MsgStartNewView:
		return "MsgStartNewView"
	case m == MsgTryPropose:
		return "MsgTryPropose"

	default:
		return "unknown"
	}
}

const (
	PhasePrepare    = iota
	PhaseTryPropose // pseudo phase, used to describe the phase between onNewView and Propose successfully
	PhasePreCommit
	PhaseCommit
	PhaseDecide
	PhaseFinal
)

func readablePhase(code uint32) string {
	switch {
	case code == PhasePrepare:
		return "PhasePrepare"
	case code == PhaseTryPropose:
		return "PhasePropose"
	case code == PhasePreCommit:
		return "PhasePreCommit"
	case code == PhaseCommit:
		return "PhaseCommit"
	case code == PhaseDecide:
		return "PhaseDecide"
	case code == PhaseFinal:
		return "PhaseFinal"
	default:
		return "unknown"
	}
}

// Proposed K or T state with signature and mask, only for OnViewDone() interface
type SignedState struct {
	State []byte
	Sign  []byte
	Mask  []byte
}

type HotStuffApplication interface {
	Self() string
	Write(string, *HotstuffMessage) error
	Broadcast(*HotstuffMessage) []error

	GetPublicKey() []*bls.PublicKey

	OnNewView(currentState []byte, extra [][]byte) error
	OnPropose(state []byte, extra []byte) error
	OnViewDone(tSign *SignedState) error

	CheckView(currentState []byte) error
	Propose() (e error, kState []byte, tState []byte, extra []byte)
	CurrentState() ([]byte, string, uint64)
	CurrentN() uint64
	GetExtra() []byte // only for new-view procedure
}

type VoteInfo struct {
	Index      int // index in the group public keys
	PubKey     *bls.PublicKey
	KSign      bls.Sign
	TSign      bls.Sign
	ValidKSign bool
	ValidTSign bool
}

type QC struct {
	kSign *bls.Sign
	tSign *bls.Sign
	mask  []byte
}

type HotstuffMessage struct {
	Code   uint32
	Number uint64
	ViewId common.Hash
	Id     string
	PubKey []byte

	// The usage of these "DataX" if different per message
	DataA []byte
	DataB []byte
	DataC []byte

	DataD []byte
	DataE []byte
	DataF []byte

	ReceivedAt time.Time
}

type View struct {
	hash           common.Hash // hash on "currentState + leaderId", hence should be unique and equal for the same view and leader
	createdAt      time.Time
	number         uint64
	leaderId       string
	phaseAsLeader  uint32
	phaseAsReplica uint32
	currentState   []byte
	proposedKState []byte
	proposedTState []byte

	highVoteInfo      []*VoteInfo
	prepareVoteInfo   []*VoteInfo
	preCommitVoteInfo []*VoteInfo
	commitVoteInfo    []*VoteInfo
	qc                map[string]*QC
	leaderMsg         map[uint64]*HotstuffMessage // record messages from leader to replica: MsgPrepare, MsgPreCommit, MsgCommit, MsgDecide

	groupPublicKey []*bls.PublicKey
	threshold      int
	cmLen          int

	extra [][]byte

	futureNewViewMsg []*HotstuffMessage

	waitingMoreVoteInfo   bool
	waitingMoreVoteInfoAt time.Time
}

func (v *View) hasKState() bool {
	return v.proposedKState != nil && len(v.proposedKState) > 0
}

func (v *View) hasTState() bool {
	return v.proposedTState != nil && len(v.proposedTState) > 0
}

type HotstuffProtocolManager struct {
	secretKey    *bls.SecretKey
	publicKey    *bls.PublicKey
	views        map[common.Hash]*View
	leaderView   *View
	app          HotStuffApplication
	unhandledMsg map[common.Hash]*HotstuffMessage // messages which is not handled(which phase is ahead of local's)
}

func NewHotstuffProtocolManager(a HotStuffApplication, secretKey *bls.SecretKey, publicKey *bls.PublicKey) *HotstuffProtocolManager {
	manager := &HotstuffProtocolManager{
		secretKey:    secretKey,
		publicKey:    publicKey,
		app:          a,
		views:        make(map[common.Hash]*View),
		unhandledMsg: make(map[common.Hash]*HotstuffMessage),
	}
	return manager
}

func CalcThreshold(size int) int {
	return (size + 1) * 2 / 3
}

func (hsm *HotstuffProtocolManager) UpdateKeyPair(sec *bls.SecretKey) {
	hsm.secretKey = sec
	hsm.publicKey = sec.GetPublicKey()
}

func (v *View) lookupReplica(pubKey *bls.PublicKey) int {
	for i, p := range v.groupPublicKey {
		if p.IsEqual(pubKey) {
			return i
		}
	}
	/*??
	log.Debug("lookupReplica miss replica's public key", "key", hex.EncodeToString(pubKey.Serialize()))

	log.Debug("lookupReplica start dumping committee members' public key ====================")
	for i, p := range v.groupPublicKey {
		log.Debug("Public Key", "index", i, "key", hex.EncodeToString(p.Serialize()))
	}
	log.Debug("lookupReplica finish dumping committee members' public key ====================")
	*/
	return -1
}

func (v *View) msgToVoteInfo(m *HotstuffMessage) (error, *VoteInfo) {
	var qrum VoteInfo
	qrum.PubKey = bls.GetPublicKey(m.PubKey)
	if qrum.PubKey == nil {
		return ErrInvalidPublicKey, nil
	}
	/*
		if err := qrum.PubKey.Deserialize(m.PubKey); err != nil {
			return err, nil
		}
	*/
	if m.DataB != nil && len(m.DataB) > 0 {
		if err := qrum.KSign.Deserialize(m.DataB); err != nil {
			qrum.ValidKSign = false
		} else {
			qrum.ValidKSign = true
		}
	}

	if m.DataC != nil && len(m.DataC) > 0 {
		if err := qrum.TSign.Deserialize(m.DataC); err != nil {
			qrum.ValidTSign = false
		} else {
			qrum.ValidTSign = true
		}
	}

	if !qrum.ValidKSign && !qrum.ValidTSign {
		return ErrInvalidVoteInfoMessage, nil
	}

	index := v.lookupReplica(qrum.PubKey)
	if -1 == index {
		return ErrInvalidReplica, nil
	}
	qrum.Index = index

	return nil, &qrum
}

func (hsm *HotstuffProtocolManager) newMsg(code uint32, number uint64, viewId common.Hash, a []byte, b []byte, c []byte) *HotstuffMessage {
	msg := &HotstuffMessage{
		Code:   code,
		Number: number,
		ViewId: viewId,
		Id:     hsm.app.Self(),
	}

	if hsm.publicKey != nil {
		bPubKey := hsm.publicKey.Serialize()
		msg.PubKey = make([]byte, len(bPubKey))
		copy(msg.PubKey, bPubKey)
	}

	if a != nil && len(a) > 0 {
		msg.DataA = make([]byte, len(a))
		copy(msg.DataA, a)
	}

	if b != nil && len(b) > 0 {
		msg.DataB = make([]byte, len(b))
		copy(msg.DataB, b)
	}

	if c != nil && len(c) > 0 {
		msg.DataC = make([]byte, len(c))
		copy(msg.DataC, c)
	}

	return msg
}

func (hsm *HotstuffProtocolManager) newView() (*View, []byte) {
	currentState, leaderId, number := hsm.app.CurrentState()
	if leaderId == "" {
		return nil, nil
	}

	v := &View{
		phaseAsReplica:    PhasePrepare,
		number:            number,
		leaderId:          leaderId,
		highVoteInfo:      make([]*VoteInfo, 0),
		prepareVoteInfo:   make([]*VoteInfo, 0),
		preCommitVoteInfo: make([]*VoteInfo, 0),
		commitVoteInfo:    make([]*VoteInfo, 0),
		qc:                make(map[string]*QC),
		leaderMsg:         make(map[uint64]*HotstuffMessage),
		extra:             make([][]byte, 0),
		futureNewViewMsg:  make([]*HotstuffMessage, 0),
		createdAt:         time.Now(),
	}

	v.currentState = make([]byte, len(currentState))
	copy(v.currentState, currentState)

	v.hash = crypto.Keccak256Hash([]byte(v.leaderId), v.currentState)

	groupPublicKey := hsm.app.GetPublicKey()
	v.groupPublicKey = make([]*bls.PublicKey, 0)
	for _, p := range groupPublicKey {
		v.groupPublicKey = append(v.groupPublicKey, p)
	}
	v.cmLen = len(groupPublicKey)
	v.threshold = CalcThreshold(v.cmLen)

	return v, hsm.app.GetExtra()
}

func (hsm *HotstuffProtocolManager) createView(asLeader bool, phase uint32, leaderId string, currentState []byte, number uint64) *View {
	v := &View{
		number:            number,
		leaderId:          leaderId,
		highVoteInfo:      make([]*VoteInfo, 0),
		prepareVoteInfo:   make([]*VoteInfo, 0),
		preCommitVoteInfo: make([]*VoteInfo, 0),
		commitVoteInfo:    make([]*VoteInfo, 0),
		qc:                make(map[string]*QC),
		leaderMsg:         make(map[uint64]*HotstuffMessage),
		extra:             make([][]byte, 0),
		futureNewViewMsg:  make([]*HotstuffMessage, 0),
		createdAt:         time.Now(),
	}

	if asLeader {
		v.phaseAsLeader = phase
	} else {
		v.phaseAsReplica = phase
	}

	v.currentState = make([]byte, len(currentState))
	copy(v.currentState, currentState)

	v.hash = crypto.Keccak256Hash([]byte(v.leaderId), v.currentState)

	groupPublicKey := hsm.app.GetPublicKey()
	v.groupPublicKey = make([]*bls.PublicKey, 0)
	for _, p := range groupPublicKey {
		v.groupPublicKey = append(v.groupPublicKey, p)
	}
	v.cmLen = len(groupPublicKey)
	v.threshold = CalcThreshold(v.cmLen)

	return v
}

func (hsm *HotstuffProtocolManager) updateViewPublicKey(v *View) {
	groupPublicKey := hsm.app.GetPublicKey()
	v.groupPublicKey = make([]*bls.PublicKey, 0)
	for _, p := range groupPublicKey {
		v.groupPublicKey = append(v.groupPublicKey, p)
	}
}

func (hsm *HotstuffProtocolManager) DumpView(v *View, asLeader bool) {
	/*
		log.Debug("Dump View ================", "viewID", v.hash)

		if asLeader {
			log.Debug("View phase", "asLeader", readablePhase(v.phaseAsLeader))
		} else {
			log.Debug("View phase", "asReplica", readablePhase(v.phaseAsLeader))
		}

		for i, p := range v.groupPublicKey {
			if i == 0 || i == 1 || i == (len(v.groupPublicKey)-1) {
				log.Debug("Public Key", "index", i, "key", hex.EncodeToString(p.Serialize()))
			}
		}

		log.Debug("Dump View End ================>>")
	*/
}

func (hsm *HotstuffProtocolManager) lockView(v *View) {
	for k, view := range hsm.views {
		if bytes.Equal(v.hash[:], view.hash[:]) {
			continue
		}

		// reserve views with future new view message
		if len(view.futureNewViewMsg) > 0 {
			continue
		}

		log.Debug("lockView remove view", "viewId", k)
		delete(hsm.views, k)
	}
}

func (hsm *HotstuffProtocolManager) viewDone(v *View, kSign []byte, tSign []byte, mask []byte, e error) {
	if e != nil {
		log.Warn("view finished with error", "error", e, "ViewId", v.hash)
		hsm.app.OnViewDone(nil)
	} else {
		elapsed := time.Now().Sub(v.createdAt).Nanoseconds() / 1000000

		log.Debug("view finished successfully", "ViewId", v.hash, "timeElapsed", elapsed)

		var tSignedState *SignedState
		if v.hasTState() {
			tSignedState = &SignedState{
				State: v.proposedTState,
				Sign:  tSign,
				Mask:  mask,
			}
		}

		hsm.app.OnViewDone(tSignedState)
	}
}

func (hsm *HotstuffProtocolManager) clearTimeoutView(curN uint64) error {
	now := time.Now()
	for _, v := range hsm.views {
		if v.number < curN {
			log.Debug("Remove timeout view", "viewId", v.hash, "phase", readablePhase(v.phaseAsReplica), "pas time", now.Sub(v.createdAt).Seconds())
			if v.phaseAsReplica < PhaseFinal {
				hsm.viewDone(v, nil, nil, nil, ErrViewTimeout)
			}
			delete(hsm.views, v.hash)
		}
	}

	for k, m := range hsm.unhandledMsg {
		if m.Number < curN {
			log.Debug("Remove unhandled hotstuff message", "viewId", m.ViewId, "code", m.Code, "from", m.Id, "past time", now.Sub(m.ReceivedAt).Seconds())
			delete(hsm.unhandledMsg, k)
		}
	}

	return nil
}

// for replica
func (hsm *HotstuffProtocolManager) NewView() error {
	v, extra := hsm.newView()
	if v == nil {
		return ErrNewViewFail
	}

	if _, exist := hsm.views[v.hash]; !exist {
		hsm.views[v.hash] = v
	}

	sig := hsm.SignHash(v.currentState)
	msg := hsm.newMsg(MsgNewView, v.number, v.hash, v.currentState, sig, extra)

	log.Debug("New View", "leader", v.leaderId, "ViewID", common.HexString(v.hash[:]))
	err := hsm.app.Write(v.leaderId, msg)
	if err != nil {
		hsm.clearTimeoutView(v.number) //clear old view
	}

	return err
}

func (hsm *HotstuffProtocolManager) aggregateQC(v *View, phase string, qrum []*VoteInfo) error {
	var kSign bls.Sign
	var tSign bls.Sign

	hasKSign := false
	hasTSign := false

	size := len(v.groupPublicKey) >> 3
	if len(v.groupPublicKey)&0x7 > 0 {
		size += 1
	}

	mask := make([]byte, size)
	for i, q := range qrum {
		if i == 0 {
			if q.ValidKSign {
				if err := kSign.Deserialize(q.KSign.Serialize()); err != nil {
					return err
				}
				hasKSign = true
			}

			if q.ValidTSign {
				if err := tSign.Deserialize(q.TSign.Serialize()); err != nil {
					return err
				}
				hasTSign = true
			}
		} else {
			if q.ValidKSign {
				kSign.Add(&q.KSign)
				hasKSign = true
			}

			if q.ValidTSign {
				tSign.Add(&q.TSign)
				hasTSign = true
			}
		}
		mask[q.Index>>3] |= 1 << uint64(q.Index%8)
	}

	v.qc[phase] = &QC{
		mask: mask,
	}

	if hasKSign {
		v.qc[phase].kSign = &kSign
	}

	if hasTSign {
		v.qc[phase].tSign = &tSign
	}

	return nil
}

func (hsm *HotstuffProtocolManager) lookupVoteInfo(pubKey *bls.PublicKey, voteInfo []*VoteInfo) bool {
	for _, q := range voteInfo {
		if q.PubKey.IsEqual(pubKey) {
			return true
		}
	}

	return false
}

// for leader
func (hsm *HotstuffProtocolManager) handleNewViewMsg(msg *HotstuffMessage) error {

	//start := time.Now()
	//defer func() {
	//	handleTime := time.Now().Sub(start).Nanoseconds() / 1000000
	//	log.Debug("handleNewViewMsg handle time", "ellpased", handleTime)
	//}()

	log.Info("handleNewViewMsg got new view message", "from", msg.Id, "viewId", msg.ViewId)
	err := hsm.app.CheckView(msg.DataA)
	if err == ErrOldState {
		log.Warn("check new view failed, discard", "viewID", msg.ViewId)
		return err
	}

	v, exist := hsm.views[msg.ViewId]
	if !exist {
		v = hsm.createView(true, PhasePrepare, hsm.app.Self(), msg.DataA, msg.Number)
		log.Debug("create new view", "leader", v.leaderId, "viewID", v.hash)
		hsm.views[v.hash] = v
	}

	v.futureNewViewMsg = append(v.futureNewViewMsg, msg)
	if err == ErrFutureState {
		log.Warn("new view got future state ", "viewID", msg.ViewId)
		return err
	}

	hsm.updateViewPublicKey(v)

	for _, m := range v.futureNewViewMsg {
		err, qrum := v.msgToVoteInfo(m)
		if err != nil {
			log.Debug("New view message failed to convert to voteInfo", "error", err)
			continue
		}

		if !qrum.KSign.VerifyHash(qrum.PubKey, crypto.Keccak256(m.DataA)) {
			log.Debug("New view message failed to verify voteInfo")
			err = ErrQCVerification
			continue
		}

		if v.hash != m.ViewId {
			log.Debug("handleNewViewMsg got new-view message with un-matched view id", "from", m.Id, "viewId", m.ViewId)
			err = ErrViewIdNotMatch
			continue
		}

		// check if the new view is already received
		pubKey := bls.GetPublicKey(m.PubKey)
		if pubKey == nil {
			log.Debug("new-view message has invalid public key", "from", m.Id, "viewId", m.ViewId, "pubKey", hex.EncodeToString(m.PubKey))
			continue
		}
		/*
			var pubKey bls.PublicKey
			if err := pubKey.Deserialize(m.PubKey); err != nil {
				log.Debug("new-view message has invalid public key", "from", m.Id, "viewId", m.ViewId, "pubKey", hex.EncodeToString(m.PubKey))
				continue
			}
		*/
		if hsm.lookupVoteInfo(pubKey, v.highVoteInfo) {
			log.Warn("receive dup new-view meesage", "from", m.Id, "viewId", m.ViewId)
			continue
		}

		if v.phaseAsLeader != PhasePrepare {
			log.Debug("handleNewViewMsg view phase not match", "viewID", hex.EncodeToString(v.hash[:]), "phase", readablePhase(v.phaseAsLeader), "shouldBe", readablePhase(PhasePrepare))

			if prepareMsg, ok := v.leaderMsg[MsgPrepare]; ok {
				log.Debug("handleNewViewMsg load prepare message and send to replica", "replicaId", m.Id)
				hsm.app.Write(m.Id, prepareMsg)
			}

			continue
		}

		v.highVoteInfo = append(v.highVoteInfo, qrum)
		if len(v.currentState) != len(m.DataA) {
			v.currentState = make([]byte, len(m.DataA))
			copy(v.currentState, m.DataA)
		}

		if m.DataC != nil && len(m.DataC) > 0 {
			extra := make([]byte, len(m.DataC))
			copy(extra, m.DataC)

			v.extra = append(v.extra, extra)
		}
	}

	v.futureNewViewMsg = make([]*HotstuffMessage, 0)
	if v.phaseAsLeader != PhasePrepare {
		// this happens when leader receives more new-view messages than (2f + 1) threshold
		// the leader should write the Prepare message to these late replica too
		return nil
	}

	hsm.leaderView = v

	threshold := v.threshold + 1
	if threshold > len(v.groupPublicKey) {
		threshold = len(v.groupPublicKey)
	}

	if len(v.highVoteInfo) < threshold {
		log.Info("handleNewViewMsg need more voteInfo", "threshold", v.threshold, "current", len(v.highVoteInfo))
		return ErrInsufficientQC
	}

	v.phaseAsLeader = PhaseTryPropose
	elapsed := time.Now().Sub(v.createdAt).Nanoseconds() / 1000000

	log.Debug("on new view", "ViewId", v.hash, "timeElapsed", elapsed)

	// notify app the new view only when leader has (n - f) votes
	if err := hsm.app.OnNewView(v.currentState, v.extra); err != nil {
		log.Debug("New view message failed verification", "error", err)
		return err
	}

	hsm.lockView(v)

	return hsm.TryPropose()
}

func (hsm *HotstuffProtocolManager) TryPropose() error {
	v := hsm.leaderView
	if v == nil {
		return ErrInvalidLeaderView
	}

	if v.phaseAsLeader != PhaseTryPropose {
		log.Warn("TryPropose is not called on PhaseTryPropose stage, ignore", "viewId", v.hash, "phase", v.phaseAsLeader)
		return ErrViewPhaseNotMatch
	}

	err, kProposal, tProposal, extra := hsm.app.Propose()
	if err != nil {
		log.Warn("hotstuff application failed to propose")
		return err
	}

	if err := hsm.aggregateQC(v, "high", v.highVoteInfo); err != nil {
		log.Debug("aggregate high voteInfo failed")
		return err
	}

	msg := hsm.newMsg(MsgPrepare, v.number, v.hash, kProposal, tProposal, v.qc["high"].kSign.Serialize())
	msg.DataD = make([]byte, len(v.qc["high"].mask))
	copy(msg.DataD, v.qc["high"].mask)

	msg.DataE = make([]byte, len(v.currentState))
	copy(msg.DataE, v.currentState)

	if extra != nil && len(extra) > 0 {
		msg.DataF = make([]byte, len(extra))
		copy(msg.DataF, extra)
	}

	log.Debug("view broadcast Prepare msg", "viewID", v.hash)
	hsm.app.Broadcast(msg)
	v.leaderMsg[MsgPrepare] = msg

	if kProposal != nil && len(kProposal) > 0 {
		v.proposedKState = make([]byte, len(kProposal))
		copy(v.proposedKState, kProposal)
	}

	if tProposal != nil && len(tProposal) > 0 {
		v.proposedTState = make([]byte, len(tProposal))
		copy(v.proposedTState, tProposal)
	}

	v.phaseAsLeader = PhasePreCommit
	hsm.leaderView = nil

	hsm.DumpView(v, true)
	return nil
}

func VerifySignature(bSign []byte, bMask []byte, data []byte, groupPublicKey []*bls.PublicKey, threshold int) bool {
	var sign bls.Sign
	if err := sign.Deserialize(bSign); err != nil {
		return false
	}

	isFirst := true
	var pub bls.PublicKey

	signer := 0

loop:
	for i := range bMask {
		ii := i << 3
		for bit := 0; bit < 8; bit++ {
			if ii+bit >= len(groupPublicKey) {
				break loop
			}

			if bMask[i]&(1<<uint(bit)) != 0 {
				if isFirst {
					pub.Deserialize(groupPublicKey[ii+bit].Serialize())
					isFirst = false
				} else {
					pub.Add(groupPublicKey[ii+bit])
				}

				signer += 1
			}
		}
	}

	if signer < threshold || !sign.VerifyHash(&pub, crypto.Keccak256(data)) {
		log.Debug("Dump failed signature ================")
		log.Debug("signer", "is", signer, "threshold", threshold)
		log.Debug("Signature", "is ", hex.EncodeToString(bSign))
		log.Debug("Mask     ", "is ", hex.EncodeToString(bMask))
		log.Debug("Data     ", "is ", hex.EncodeToString(data))

		for i, p := range groupPublicKey {
			log.Debug("Public Key", "index", i, "key", hex.EncodeToString(p.Serialize()))
		}

		log.Debug("Dump failed signature end =================>>")
		return false
	}

	return true
}

func MaskToException(bMask []byte, groupPublicKey []*bls.PublicKey, beNewVer bool) []*bls.PublicKey {
	exception := make([]*bls.PublicKey, 0)
loop:
	for i := range bMask {
		ii := i << 3
		for bit := 0; bit < 8; bit++ {
			if ii+bit >= len(groupPublicKey) {
				break loop
			}
			if beNewVer {
				if bMask[i]&(1<<uint(bit)) == 0 {
					exception = append(exception, groupPublicKey[ii+bit])
				}
			} else {
				if bMask[i]&(1<<uint(bit)) != 0 {
					exception = append(exception, groupPublicKey[ii+bit])
				}
			}
		}
	}

	return exception
}

func MaskToExceptionIndexs(bMask []byte, cmLen int) []int {
	exception := make([]int, 0)
loop:
	for i := range bMask {
		ii := i << 3
		for bit := 0; bit < 8; bit++ {
			if ii+bit >= cmLen {
				break loop
			}
			if bMask[i]&(1<<uint(bit)) == 0 {
				exception = append(exception, ii+bit)
			}
		}
	}

	return exception
}

// for replica
func (hsm *HotstuffProtocolManager) handlePrepareMsg(m *HotstuffMessage) error {
	v, exist := hsm.views[m.ViewId]
	if !exist {
		v = hsm.createView(false, PhasePrepare, m.Id, m.DataE, m.Number)
		hsm.views[v.hash] = v
		log.Debug("handlePrepareMsg create view", "viewId", m.ViewId)
	}

	if v.phaseAsReplica != PhasePrepare {
		log.Trace("handlePrepareMsg discard old-phase message", "viewId", hex.EncodeToString(m.ViewId[:]), "phase", readablePhase(v.phaseAsReplica))
		//fmt.Println("handlePrepareMsg discard old-phase message", "viewId", hex.EncodeToString(m.ViewId[:]), "phase", readablePhase(v.phaseAsReplica))
		return ErrViewPhaseNotMatch
	}

	var state, extra []byte
	if len(m.DataB) > 0 {
		state = m.DataB
	}

	if len(m.DataF) > 0 {
		extra = m.DataF
	}

	// verify highQC in the prepare msg
	if !VerifySignature(m.DataC, m.DataD, m.DataE, v.groupPublicKey, v.threshold) {
		log.Debug("handlePrepareMsg failed to verify highQC", "viewId", m.ViewId)
		return ErrInvalidHighQC
	}

	if err := hsm.app.OnPropose(state, extra); err != nil {
		log.Debug("handlePrepareMsg failed to verify proposed data", "viewId", m.ViewId)
		return ErrInvalidProposal
	}
	hsm.lockView(v)

	kSign := []byte(nil)
	tSign := []byte(nil)

	if m.DataA != nil && len(m.DataA) > 0 {
		v.proposedKState = make([]byte, len(m.DataA))
		copy(v.proposedKState, m.DataA)

		kSign = hsm.SignHash(v.proposedKState)
	}

	if m.DataB != nil && len(m.DataB) > 0 {
		v.proposedTState = make([]byte, len(m.DataB))
		copy(v.proposedTState, m.DataB)

		tSign = hsm.SignHash(v.proposedTState)
	}

	msg := hsm.newMsg(MsgVotePrepare, v.number, v.hash, nil, kSign, tSign)

	log.Debug("handlePrepareMsg send VotePrepare msg", "viewID", v.hash)
	hsm.app.Write(m.Id, msg)
	v.phaseAsReplica = PhaseDecide

	return nil
}

func (hsm *HotstuffProtocolManager) createSignatureMsg(v *View, code uint32, phase string) *HotstuffMessage {
	bKSign := []byte(nil)
	bTSign := []byte(nil)
	if v.qc[phase].kSign != nil {
		bKSign = v.qc[phase].kSign.Serialize()
	}
	if v.qc[phase].tSign != nil {
		bTSign = v.qc[phase].tSign.Serialize()
	}

	// DataA: kSign, DataB: tSign, DataC: mask
	return hsm.newMsg(code, v.number, v.hash, bKSign, bTSign, v.qc[phase].mask)
}

// for leader
func (hsm *HotstuffProtocolManager) handlePrepareVoteMsg(m *HotstuffMessage) error {
	v, exist := hsm.views[m.ViewId]
	if !exist {
		log.Debug("handlePrepareVoteMsg found no matched view", "viewId", m.ViewId)
		return ErrMissingView
	}

	err, qrum := v.msgToVoteInfo(m)
	if err != nil {
		log.Debug("handlePrepareVoteMsg failed to convert msg to voteInfo", "error", err)
		return err
	}

	if v.hasKState() {
		if !qrum.ValidKSign || !qrum.KSign.VerifyHash(qrum.PubKey, crypto.Keccak256(v.proposedKState)) {
			log.Debug("handlePrepareVoteMsg failed to verify k-state signature", "viewId", m.ViewId)
			return ErrQCVerification
		}
	}

	if v.hasTState() {
		if !qrum.ValidTSign || !qrum.TSign.VerifyHash(qrum.PubKey, crypto.Keccak256(v.proposedTState)) {
			log.Debug("handlePrepareVoteMsg failed to verify t-state signature", "viewId", m.ViewId)
			hsm.DumpView(v, true)
			return ErrQCVerification
		}
	}

	if v.phaseAsLeader != PhasePreCommit {
		log.Trace("handlePrepareVoteMsg view phase not match", "viewID", hex.EncodeToString(v.hash[:]), "phase", readablePhase(v.phaseAsLeader), "shouldBe", readablePhase(PhasePreCommit))

		if preCommitMsg, ok := v.leaderMsg[MsgPreCommit]; ok {
			log.Debug("handlePrepareVoteMsg load PreCommit message and send to replica", "replicaId", m.Id)
			hsm.app.Write(m.Id, preCommitMsg)

			return nil
		}

		return ErrViewPhaseNotMatch
	}
	pubKey := bls.GetPublicKey(m.PubKey)
	if pubKey == nil {
		log.Warn("prepare-vote message has invalid public key", "from", m.Id, "viewId", m.ViewId, "pubKey", hex.EncodeToString(m.PubKey))
		return nil
	}
	/*
		var pubKey bls.PublicKey
		if err := pubKey.Deserialize(m.PubKey); err != nil {
			log.Warn("prepare-vote message has invalid public key", "from", m.Id, "viewId", m.ViewId, "pubKey", hex.EncodeToString(m.PubKey))
			return nil
		}
	*/
	if hsm.lookupVoteInfo(pubKey, v.prepareVoteInfo) {
		log.Warn("discard dup prepare-vote message", "from", m.Id, "viewId", m.ViewId)
		return nil
	}

	v.prepareVoteInfo = append(v.prepareVoteInfo, qrum)
	if len(v.prepareVoteInfo) < v.threshold {
		log.Debug("handlePrepareVoteMsg need more voteInfo", "number", v.number, "threshold", v.threshold, "current", len(v.prepareVoteInfo))
		return ErrInsufficientQC
	}

	isTimeout := false
	if v.waitingMoreVoteInfo {
		elapsed := time.Now().Sub(v.waitingMoreVoteInfoAt)
		log.Debug("@@@handlePrepareVoteMsg collect sufficient votes", "viewId", m.ViewId, "number", v.number, "elapsed(s)", elapsed)
		if elapsed >= params.CollectVoteInfoTimeout {
			isTimeout = true
		}
	}

	if !isTimeout && len(v.prepareVoteInfo) < v.cmLen-1 {
		if !v.waitingMoreVoteInfo {
			v.waitingMoreVoteInfo = true
			v.waitingMoreVoteInfoAt = time.Now()
		}
		return nil
	}
	v.waitingMoreVoteInfo = false
	if err := hsm.aggregateQC(v, "prepare", v.prepareVoteInfo); err != nil {
		log.Debug("aggregate prepare voteInfo failed")
		return err
	}

	msg := hsm.createSignatureMsg(v, MsgDecide, "prepare")

	log.Debug("handlePrepareVoteMsg broadcast Decide msg", "viewId", m.ViewId, "number", v.number)
	hsm.app.Broadcast(msg)
	v.phaseAsLeader = PhaseFinal
	v.leaderMsg[MsgDecide] = msg

	return nil
}

// for replica
func (hsm *HotstuffProtocolManager) handleDecideMsg(m *HotstuffMessage) error {
	v, exist := hsm.views[m.ViewId]
	if !exist {
		//log.Debug("handleDecideMsg found no match view", "viewId", m.ViewId)
		return ErrMissingView
		//return ErrUnhandledMsg
	}

	//if v.phaseAsReplica < PhaseDecide {
	//	log.Debug("handleDecideMsg got future phase message", "viewId", hex.EncodeToString(m.ViewId[:]), "phase", readablePhase(v.phaseAsReplica))
	//	return ErrUnhandledMsg
	//}

	if v.phaseAsReplica > PhaseDecide {
		log.Trace("handleDecideMsg discard old phase message", "viewId", hex.EncodeToString(m.ViewId[:]), "phase", readablePhase(v.phaseAsReplica))
		return ErrViewOldPhase
	}

	if v.hasTState() {
		if !VerifySignature(m.DataB, m.DataC, v.proposedTState, v.groupPublicKey, v.threshold) {
			log.Debug("handleDecideMsg failed to verify aggregated t-state signature", "viewId", m.ViewId)
			hsm.DumpView(v, false)
			return ErrInvalidPrepareQC
		}
	}

	log.Debug("handleDecideMsg view done", "viewId", m.ViewId)

	// execute the command
	hsm.viewDone(v, m.DataA, m.DataB, m.DataC, nil)
	v.phaseAsReplica = PhaseFinal

	// start new view
	//hsm.NewView()

	return nil
}

func (hsm *HotstuffProtocolManager) handleMessage(m *HotstuffMessage) error {
	switch {
	case m.Code == MsgTimer:
		return hsm.handleTimerMsg(m.Number)

	case m.Code == MsgNewView:
		return hsm.handleNewViewMsg(m)

	case m.Code == MsgPrepare:
		return hsm.handlePrepareMsg(m)
	case m.Code == MsgVotePrepare:
		return hsm.handlePrepareVoteMsg(m)
		/*
			case m.Code == MsgPreCommit:
				return hsm.handlePreCommitMsg(m)
			case m.Code == MsgVotePreCommit:
				return hsm.handlePreCommitVoteMsg(m)

			case m.Code == MsgCommit:
				return hsm.handleCommitMsg(m)
			case m.Code == MsgVoteCommit:
				return hsm.handleCommitVoteMsg(m)
		*/
	case m.Code == MsgDecide:
		return hsm.handleDecideMsg(m)
	//empty message
	case m.Code == MsgStartNewView:
		log.Debug("handler handleStartNewView")
		return hsm.NewView()
	case m.Code == MsgTryPropose:
		log.Debug("handler MsgTryPropose")
		return hsm.TryPropose()

	default:
		log.Warn("unknown hotstuff message", "code", m.Code)
		return nil
	}
}

func (hsm *HotstuffProtocolManager) addToUnhandled(m *HotstuffMessage) {
	if m.Number < hsm.app.CurrentN() {
		return
	}
	bs, err := rlp.EncodeToBytes(m)
	if err != nil {
		log.Warn("failed to encode hotstuff message to bytes, discarded")
		return
	}
	m.ReceivedAt = time.Now() //??

	k := crypto.Keccak256Hash(bs)
	hsm.unhandledMsg[k] = m
}

func (hsm *HotstuffProtocolManager) HandleMessage(msg *HotstuffMessage) error {
	if msg.Code != MsgTimer {
		log.Debug("HandleMessage", "Number", msg.Number, "viewId", msg.ViewId, "code", ReadableMsgType(msg.Code), "from", msg.Id)
	}
	err := hsm.handleMessage(msg)
	if err == ErrUnhandledMsg {
		log.Debug("Add unhandled hotstuff message", "viewId", msg.ViewId, "code", msg.Code, "from", msg.Id)
		//fmt.Println("Add unhandled hotstuff message", "viewId", msg.ViewId, "code", msg.Code, "from", msg.Id)
		hsm.addToUnhandled(msg)
		return ErrUnhandledMsg
	}

	for k, m := range hsm.unhandledMsg {
		if e := hsm.handleMessage(m); e != ErrUnhandledMsg {
			log.Debug("Remove unhandled hotstuff message", "viewId", msg.ViewId, "code", msg.Code, "from", msg.Id)
			delete(hsm.unhandledMsg, k)
		}
	}

	return err
}

func (hsm *HotstuffProtocolManager) handleTimerMsg(curN uint64) error {
	for _, v := range hsm.views {
		if v.number <= curN {
			continue
		}
		if v.phaseAsLeader == PhaseFinal || !v.waitingMoreVoteInfo || len(v.prepareVoteInfo) < v.threshold {
			continue
		}
		elapsed := time.Now().Sub(v.waitingMoreVoteInfoAt)
		if elapsed < params.CollectVoteInfoTimeout {
			continue
		}

		log.Debug("@@@handleTimerMsg", "curN", curN, "number", v.number, "elapsed(s)", elapsed)
		if err := hsm.aggregateQC(v, "prepare", v.prepareVoteInfo); err != nil {
			log.Debug("aggregate prepare voteInfo failed")
			continue
		}

		log.Debug("handleTimerMsg handlePrepareVoteMsg broadcast Decide msg", "number", v.number)
		v.waitingMoreVoteInfo = false
		msg := hsm.createSignatureMsg(v, MsgDecide, "prepare")
		hsm.app.Broadcast(msg)
		v.phaseAsLeader = PhaseFinal
		v.leaderMsg[MsgDecide] = msg
	}

	return nil
}

func (hsm *HotstuffProtocolManager) SignHash(data []byte) []byte {
	sign := hsm.secretKey.SignHash(crypto.Keccak256(data)).Serialize()
	log.Info("Signed hotstuff data!")
	return sign
}
