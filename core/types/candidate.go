package types

import (
	"bytes"
	"io"
	"math/big"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/rlp"
	"github.com/pkg/errors"
)

const (
	DeterminByMinNonce = iota
	DeterminByMaxNonce
)

type Candidate struct {
	KeyCandidate *KeyBlockHeader `rlp:"nil"`
	IP           []byte
	Port         int
	PubKey       string
	Coinbase     string

	hash atomic.Value
	size atomic.Value
}

func NewCandidate(parentHash common.Hash, difficulty *big.Int, number uint64, txNumber uint64, extraByte []byte, ip []byte, pubKey string, eb string, port int) *Candidate {
	c := &Candidate{
		KeyCandidate: &KeyBlockHeader{BlockType: PowReconfig, ParentHash: parentHash, Difficulty: big.NewInt(0)},
		Port:         port,
	}
	c.KeyCandidate.Time = uint64(time.Now().Unix())

	if difficulty != nil {
		c.KeyCandidate.Difficulty.Set(difficulty)
	}

	c.KeyCandidate.Number = new(big.Int).SetUint64(number)
	c.KeyCandidate.T_Number = txNumber
	c.IP = make([]byte, len(ip))
	copy(c.IP, ip)

	c.PubKey = pubKey
	c.Coinbase = eb

	//log.Info("NewCandidate", "Coinbase", c.Coinbase, "number", number)

	return c
}

// Hash hashes the RLP encoding of candidate.
// It uniquely identifies the candidate.
func (c *Candidate) Hash() common.Hash {
	if hash := c.hash.Load(); hash != nil {
		return hash.(common.Hash)
	}
	v := rlpHash(c)
	c.hash.Store(v)

	return v
}

type extcandidate struct {
	KeyCandidate *KeyBlockHeader `rlp:"nil"`
	IP           []byte
	PubKey       string
	Coinbase     string
	Port         string
}

func (c *Candidate) EncodeRLP(w io.Writer) error {
	if c == nil {
		return rlp.Encode(w, extcandidate{})
	}
	return rlp.Encode(w, extcandidate{
		KeyCandidate: c.KeyCandidate,
		IP:           c.IP,
		PubKey:       c.PubKey,
		Coinbase:     c.Coinbase,
		Port:         strconv.Itoa(c.Port),
	})
}

func (c *Candidate) DecodeRLP(s *rlp.Stream) error {
	var e extcandidate
	_, size, _ := s.Kind()
	if err := s.Decode(&e); err != nil {
		return err
	}
	if string(e.IP) == "" {
		return errors.New("ip is nil")
	}
	c.KeyCandidate, c.IP, c.PubKey, c.Coinbase = e.KeyCandidate, e.IP, e.PubKey, e.Coinbase
	//log.Info("Candidate DecodeRLP", "ip", c.IP, "coinBase", c.Coinbase)
	c.Port, _ = strconv.Atoi(e.Port)
	c.size.Store(common.StorageSize(rlp.ListSize(size)))
	return nil
}

func (c *Candidate) EncodeToBytes() []byte {
	m := make([]byte, 0)
	buff := bytes.NewBuffer(m)
	err := c.EncodeRLP(buff)
	if err != nil {
		log.Error("Candidate.EncodeToBytes", "error", err)
		return nil
	}
	return buff.Bytes()
}
func DecodeToCandidate(data []byte) *Candidate {
	if data == nil {
		return nil
	}
	candi := &Candidate{}
	buff := bytes.NewBuffer(data)
	c := rlp.NewStream(buff, 0)
	err := candi.DecodeRLP(c)
	if err != nil {
		log.Error("Candidate.DecodeToCandidate", "error", err)
		return nil
	}
	return candi
}

func (c *Candidate) HashNoNonce() common.Hash {
	keyBlockHeader := &KeyBlockHeader{
		ParentHash:    c.KeyCandidate.ParentHash,
		Difficulty:    c.KeyCandidate.Difficulty,
		Number:        c.KeyCandidate.Number,
		Time:          c.KeyCandidate.Time,
		CommitteeHash: c.KeyCandidate.CommitteeHash,
		T_Number:      c.KeyCandidate.T_Number,
	}
	candidate := Candidate{IP: c.IP, KeyCandidate: keyBlockHeader, PubKey: c.PubKey, Coinbase: c.Coinbase, Port: c.Port}
	return rlpHash(candidate)
}

type Candidates []*Candidate

type CandsByNonce Candidates

func (s CandsByNonce) Len() int { return len(s) }
func (s CandsByNonce) Less(i, j int) bool {
	return s[i].KeyCandidate.Nonce.Uint64() < s[j].KeyCandidate.Nonce.Uint64()
}
func (s CandsByNonce) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
