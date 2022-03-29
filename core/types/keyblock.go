package types

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/big"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/log"
	"github.com/cypherium/cypher/rlp"
)

const (
	PowReconfig     = 1
	TimeReconfig    = 2
	PaceReconfig    = 3
	PacePowReconfig = 4
	Initialization  = 9
)

// Header represents a block header in the Cypherium blockchain.
type KeyBlockHeader struct {
	ParentHash common.Hash `json:"parentHash"       gencodec:"required"`
	Difficulty *big.Int    `json:"difficulty"       gencodec:"required"`
	Number     *big.Int    `json:"number"           gencodec:"required"`
	Time       uint64      `json:"time"  gencodec:"required"`
	BlockType  uint8       `json:"blockType"              gencodec:"required"`

	MixDigest common.Hash `json:"mixHash"          gencodec:"required"`
	Nonce     BlockNonce  `json:"nonce"            gencodec:"required"`

	CommitteeHash common.Hash `json:"committeeHash"       gencodec:"required"`
	T_Number      uint64      `json:"t_Number"  gencodec:"required"`
}

// Hash returns the hash of the key header, which is simply the keccak256 hash of its
// RLP encoding.
func (h *KeyBlockHeader) Hash() common.Hash {
	return rlpHash(h)
}
func (h *KeyBlockHeader) NumberU64() uint64 { return h.Number.Uint64() }

// HashNoNonce returns the hash which is used as input for the proof-of-work search.
func (h *KeyBlockHeader) HashWithCandi() common.Hash {
	return rlpHash([]interface{}{
		h.ParentHash,
		h.Difficulty,
		h.Number,
		h.Time,
		h.BlockType,
		h.MixDigest,
		h.Nonce,
	})
}

// Size returns the approximate memory used by all internal contents. It is used
// to approximate and limit the memory consumption of various caches.
func (h *KeyBlockHeader) Size() common.StorageSize {
	return common.StorageSize(unsafe.Sizeof(*h)) + common.StorageSize((h.Difficulty.BitLen()+h.Number.BitLen())/8)
}
func (h *KeyBlockHeader) HasNewNode() bool {
	return h.BlockType == PowReconfig || h.BlockType == PacePowReconfig
}

//go:generate gencodec -type KeyBlockBody -field-override keyBlockBodyMarshaling -out gen_key_body_json.go
type keyBlockBodyMarshaling struct {
	LeaderPubKey  string
	LeaderAddress string
	InPubKey      string
	InAddress     string
	OutPubKey     string
	OutAddress    string
}

type KeyBlockBody struct {
	LeaderPubKey  string `json:"leaderPubKey"           gencodec:"required"`
	LeaderAddress string `json:"leaderAddress"           gencodec:"required"`
	InPubKey      string `json:"inPubKey"            	gencodec:"required"`
	InAddress     string `json:"inAddress"            gencodec:"required"`
	OutPubKey     string `json:"outPubKey"            	gencodec:"required"`
	OutAddress    string `json:"outAddress"            gencodec:"required"`
}

// Block represents an entire block in the Cypherium blockchain.
type KeyBlock struct {
	header        *KeyBlockHeader
	leaderPubKey  string
	leaderAddress string
	inPubKey      string
	inAddress     string
	outPubKey     string
	outAddress    string
	// caches
	hash atomic.Value
	size atomic.Value

	// Td is used by package core to store the total difficulty
	// of the chain up to and including the block.
	td *big.Int

	// These fields are used by package eth to track
	// inter-peer block relay.
	ReceivedAt   time.Time
	ReceivedFrom interface{}
}

type KeyBlocks []*KeyBlock

type extKeyblock struct {
	Header        *KeyBlockHeader
	LeaderPubKey  string `json:"leaderPubKey"           gencodec:"required"`
	LeaderAddress string `json:"leaderAddress"           gencodec:"required"`
	InPubKey      string `json:"inPubKey"               gencodec:"required"`
	InAddress     string `json:"inAddress"            gencodec:"required"`
	OutPubKey     string `json:"outPubKey"              gencodec:"required"`
	OutAddress    string `json:"outAddress"            gencodec:"required"`
}

// NewBlock creates a new block. The input data is copied,
// changes to header and to the field values will not affect the
// block.
//
// The values of x in header
// are ignored and set to values derived from the x.
func NewKeyBlock(header *KeyBlockHeader) *KeyBlock {
	b := &KeyBlock{header: CopyKeyBlockHeader(header), td: new(big.Int)}

	return b
}

// NewBlockWithHeader creates a block with the given header data. The
// header data is copied, changes to header and to the field values
// will not affect the block.
func NewKeyBlockWithHeader(header *KeyBlockHeader) *KeyBlock {
	return &KeyBlock{header: CopyKeyBlockHeader(header)}
}

// CopyHeader creates a deep copy of a block header to prevent side effects from
// modifying a header variable.
func CopyKeyBlockHeader(h *KeyBlockHeader) *KeyBlockHeader {
	cpy := *h
	if cpy.Difficulty = new(big.Int); h.Difficulty != nil {
		cpy.Difficulty.Set(h.Difficulty)
	}
	if cpy.Number = new(big.Int); h.Number != nil {
		cpy.Number.Set(h.Number)
	}

	return &cpy
}

// DecodeRLP decodes the Cypherium
func (b *KeyBlock) DecodeRLP(s *rlp.Stream) error {
	var eb extKeyblock
	_, size, _ := s.Kind()
	if err := s.Decode(&eb); err != nil {
		return err
	}

	b.header = eb.Header
	b.leaderPubKey, b.leaderAddress = eb.LeaderPubKey, eb.LeaderAddress
	b.inPubKey, b.inAddress, b.outPubKey, b.outAddress = eb.InPubKey, eb.InAddress, eb.OutPubKey, eb.OutAddress
	b.size.Store(common.StorageSize(rlp.ListSize(size)))
	return nil
}

// EncodeRLP serializes b into the Cypherium RLP block format.
func (b *KeyBlock) EncodeRLP(w io.Writer) error {
	//if b.IsForkVer2()
	return rlp.Encode(w, extKeyblock{
		Header:        b.header,
		InPubKey:      b.inPubKey,
		InAddress:     b.inAddress,
		OutPubKey:     b.outPubKey,
		OutAddress:    b.outAddress,
		LeaderPubKey:  b.leaderPubKey,
		LeaderAddress: b.leaderAddress,
	})
}

func (b *KeyBlock) EncodeToBytes() []byte {
	m := make([]byte, 0)
	buff := bytes.NewBuffer(m)
	err := b.EncodeRLP(buff)
	if err != nil {
		log.Error("KeyBlock.EncodeToBytes", "error", err)
		return nil
	}

	return buff.Bytes()
}
func DecodeToKeyBlock(data []byte) *KeyBlock {
	if data == nil {
		return nil
	}
	block := &KeyBlock{}
	buff := bytes.NewBuffer(data)
	c := rlp.NewStream(buff, 0)
	err := block.DecodeRLP(c)
	if err != nil {
		log.Error("KeyBlock.DecodeToBlock", "error", err)
		return nil
	}
	return block
}

func (b *KeyBlock) Number() *big.Int           { return new(big.Int).Set(b.header.Number) }
func (b *KeyBlock) SetNumber(num *big.Int)     { b.header.Number = num }
func (b *KeyBlock) Difficulty() *big.Int       { return new(big.Int).Set(b.header.Difficulty) }
func (b *KeyBlock) SetDifficulty(dif *big.Int) { b.header.Difficulty = dif }
func (b *KeyBlock) Time() uint64               { return b.header.Time }
func (b *KeyBlock) SetTime(time uint64)        { b.header.Time = time }

func (b *KeyBlock) NumberU64() uint64            { return b.header.Number.Uint64() }
func (b *KeyBlock) MixDigest() common.Hash       { return b.header.MixDigest }
func (b *KeyBlock) Nonce() uint64                { return binary.BigEndian.Uint64(b.header.Nonce[:]) }
func (b *KeyBlock) ParentHash() common.Hash      { return b.header.ParentHash }
func (b *KeyBlock) BlockType() uint8             { return b.header.BlockType }
func (b *KeyBlock) SetBlockType(blockType uint8) { b.header.BlockType = blockType }

func (b *KeyBlock) CommitteeHash() common.Hash        { return b.header.CommitteeHash }
func (b *KeyBlock) SetCommitteeHash(hash common.Hash) { b.header.CommitteeHash = hash }
func GetCommitteeHash(x interface{}) common.Hash      { return rlpHash(x) }
func (b *KeyBlock) T_Number() uint64                  { return b.header.T_Number }

func (b *KeyBlock) Header() *KeyBlockHeader { return CopyKeyBlockHeader(b.header) }

func (b *KeyBlock) LeaderPubKey() string  { return b.leaderPubKey }
func (b *KeyBlock) LeaderAddress() string { return b.leaderAddress }
func (b *KeyBlock) InPubKey() string      { return b.inPubKey }
func (b *KeyBlock) InAddress() string     { return b.inAddress }
func (b *KeyBlock) OutPubKey() string     { return b.outPubKey }
func (b *KeyBlock) OutAddress(flag int) string {
	if flag == 1 && b.outAddress != "" && b.outAddress[0] == '*' {
		return b.outAddress[1:]
	}
	return b.outAddress
}
func (b *KeyBlock) HasNewNode() bool {
	return b.header.BlockType == PowReconfig || b.header.BlockType == PacePowReconfig
}
func (b *KeyBlock) TypeCheck(last_T_Number uint64) bool {
	/*
		keyType := b.BlockType()
		if keyType == PowReconfig && (b.T_Number()-last_T_Number)%params.KeyblockPerTxBlocks != 0 {
			return false
		} else if keyType == TimeReconfig && (b.T_Number()-last_T_Number)%params.GapTxBlocks != 0 {
			return false
		}
	*/
	return true
}

// Body returns the non-header content of the block.
func (b *KeyBlock) Body() *KeyBlockBody {
	keyBody := &KeyBlockBody{}

	keyBody.LeaderPubKey = b.leaderPubKey
	keyBody.LeaderAddress = b.leaderAddress
	keyBody.InPubKey = b.inPubKey
	keyBody.InAddress = b.inAddress
	keyBody.OutPubKey = b.outPubKey
	keyBody.OutAddress = b.outAddress
	return keyBody
}

// Size returns the true RLP encoded storage size of the block, either by encoding
// and returning it, or returning a previsouly cached value.
func (b *KeyBlock) Size() common.StorageSize {
	if size := b.size.Load(); size != nil {
		return size.(common.StorageSize)
	}
	c := writeCounter(0)
	rlp.Encode(&c, b)
	b.size.Store(common.StorageSize(c))
	return common.StorageSize(c)
}

// WithBody returns a new block with the given signatrue and exceptions contents.
func (b *KeyBlock) WithBody(inPubKey string, inAddress string, outPubKey string, outAddress string, leaderPubKey string, leaderAddress string) *KeyBlock {
	block := &KeyBlock{
		header: CopyKeyBlockHeader(b.header),
	}
	block.leaderPubKey = leaderPubKey
	block.leaderAddress = leaderAddress
	block.inPubKey = inPubKey
	block.inAddress = inAddress
	block.outPubKey = outPubKey
	block.outAddress = outAddress
	return block
}

func (b *KeyBlock) CopyMe() *KeyBlock {
	block := &KeyBlock{
		header: CopyKeyBlockHeader(b.header),
	}
	block.leaderPubKey = b.leaderPubKey
	block.leaderAddress = b.leaderAddress
	block.inPubKey = b.inPubKey
	block.inAddress = b.inAddress
	block.outPubKey = b.outPubKey
	block.outAddress = b.outAddress
	return block
}

// Hash returns the keccak256 hash of b's header.
// The hash is computed on the first call and cached thereafter.
func (b *KeyBlock) Hash() common.Hash {
	if hash := b.hash.Load(); hash != nil {
		return hash.(common.Hash)
	}
	v := b.header.Hash()
	b.hash.Store(v)
	return v
}
