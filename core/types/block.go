// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package types contains data types related to Ethereum consensus.
package types

import (
	"bytes"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/common/hexutil"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/params"
	"github.com/cypherium/cypher/rlp"
	"golang.org/x/crypto/sha3"
)

var (
	EmptyRootHash   = common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
	ExtraKeyOffset  = 32
	ExtraKeyMinSize = 128
)

const (
	Normal_Block uint8 = iota
	Key_Block
)

//go:generate gencodec -type Header -field-override headerMarshaling -out gen_header_json.go
// Header represents a block header in the Cypherium blockchain.
type Header struct {
	ParentHash  common.Hash `json:"parentHash"       gencodec:"required"`
	Root        common.Hash `json:"stateRoot"        gencodec:"required"`
	TxHash      common.Hash `json:"transactionsRoot" gencodec:"required"`
	ReceiptHash common.Hash `json:"receiptsRoot"     gencodec:"required"`
	Number      *big.Int    `json:"number"           gencodec:"required"`
	GasLimit    uint64      `json:"gasLimit"         gencodec:"required"`
	GasUsed     uint64      `json:"gasUsed"          gencodec:"required"`
	Time        uint64      `json:"timestamp"        gencodec:"required"`
	BlockType   uint8       `json:"blockType"      gencodec:"required"`
	KeyHash     common.Hash `json:"keyHash"       gencodec:"required"`
	Extra       []byte      `json:"extraData"        gencodec:"required"`
	Signature   []byte      `json:"signature"     gencodec:"required"`
	Exceptions  []byte      `json:"exceptions"       gencodec:"required"`
}

// field type overrides for gencodec
type headerMarshaling struct {
	Number   *hexutil.Big
	GasLimit hexutil.Uint64
	GasUsed  hexutil.Uint64
	Time     *hexutil.Big
	Extra    hexutil.Bytes
	Hash     common.Hash `json:"hash"` // adds call to Hash() in MarshalJSON
}

// Hash returns the block hash of the header, which is simply the keccak256 hash of its
// RLP encoding.
func (h *Header) Hash() common.Hash {
	var extra []byte
	n := h.Number.Uint64()
	if n == 0 || n >= params.ForkNewVerBlock { //for old blockchain
		extra = h.Extra
	}
	return rlpHash([]interface{}{
		h.ParentHash,
		h.Root,
		h.TxHash,
		h.ReceiptHash,
		h.Number,
		h.GasLimit,
		h.GasUsed,
		h.Time,
		h.BlockType,
		h.KeyHash,
		extra,
	})
}

func (h *Header) SetSignInfoNull() {
	h.Signature = nil
	h.Exceptions = nil
}
func (h *Header) NumberU64() uint64 { return h.Number.Uint64() }

var headerSize = common.StorageSize(reflect.TypeOf(Header{}).Size())

// Size returns the approximate memory used by all internal contents. It is used
// to approximate and limit the memory consumption of various caches.
func (h *Header) Size() common.StorageSize {
	s := headerSize + common.StorageSize(len(h.Extra)+h.Number.BitLen()/8+len(h.Signature)+len(h.Exceptions))
	return s
}

// SanityCheck checks a few basic things -- these checks are way beyond what
// any 'sane' production values should hold, and can mainly be used to prevent
// that the unbounded fields are stuffed with junk data to add processing
// overhead
func (h *Header) SanityCheck() error {
	if h.Number != nil && !h.Number.IsUint64() {
		return fmt.Errorf("too large block number: bitlen %d", h.Number.BitLen())
	}
	if eLen := len(h.Extra); eLen > 100*1024 {
		return fmt.Errorf("too large block extradata: size %d", eLen)
	}
	return nil
}

// hasherPool holds LegacyKeccak hashers.
var hasherPool = sync.Pool{
	New: func() interface{} {
		return sha3.NewLegacyKeccak256()
	},
}

func rlpHash(x interface{}) (h common.Hash) {
	sha := hasherPool.Get().(crypto.KeccakState)
	defer hasherPool.Put(sha)
	sha.Reset()
	rlp.Encode(sha, x)
	sha.Read(h[:])
	return h
}

// EmptyBody returns true if there is no additional 'body' to complete the header
// that is: no transactions .
func (h *Header) EmptyBody() bool {
	return h.TxHash == EmptyRootHash
}

// EmptyReceipts returns true if there are no receipts for this header/block.
func (h *Header) EmptyReceipts() bool {
	return h.ReceiptHash == EmptyRootHash
}

func (h *Header) Difficulty() *big.Int {
	kb := getKeyBlockByHash(h.KeyHash)
	if kb != nil {
		return kb.Difficulty()
	}
	return big.NewInt(1)
}
func (h *Header) Coinbase() common.Address {
	kb := getKeyBlockByHash(h.KeyHash)
	if kb != nil {
		return common.HexToAddress(kb.LeaderAddress())
	}
	return common.Address{}
}

// Body is a simple (mutable, non-safe) data container for storing and moving
// a block's data contents (transactions ) together.
type Body struct {
	Transactions []*Transaction
}

// Block represents an entire block in the Ethereum blockchain.
type Block struct {
	header       *Header
	transactions Transactions

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

func (b *Block) String() string {
	return fmt.Sprintf("{Header: %v}", b.header)
}

// DeprecatedTd is an old relic for extracting the TD of a block. It is in the
// code solely to facilitate upgrading the database from the old format to the
// new, after which it should be deleted. Do not use!
func (b *Block) DeprecatedTd() *big.Int {
	return b.td
}

// [deprecated by eth/63]
// StorageBlock defines the RLP encoding of a Block stored in the
// state database. The StorageBlock encoding contains fields that
// would otherwise need to be recomputed.
type StorageBlock Block

// "external" block encoding. used for eth protocol, etc.
type extblock struct {
	Header *Header
	Txs    []*Transaction
}

// [deprecated by eth/63]
// "storage" block encoding. used for database.
type storageblock struct {
	Header *Header
	Txs    []*Transaction
	TD     *big.Int
}

// NewBlock creates a new block. The input data is copied,
// changes to header and to the field values will not affect the
// block.
//
// The values of TxHash, ReceiptHash and Bloom in header
// are ignored and set to values derived from the given txs
// and receipts.
func NewBlock(header *Header, txs []*Transaction, receipts []*Receipt, hasher Hasher) *Block {
	b := &Block{header: CopyHeader(header), td: new(big.Int)}

	// TODO: panic if len(txs) != len(receipts)
	if len(txs) == 0 {
		b.header.TxHash = EmptyRootHash
	} else {
		b.header.TxHash = DeriveSha(Transactions(txs), hasher)
		b.transactions = make(Transactions, len(txs))
		copy(b.transactions, txs)
	}

	if len(receipts) == 0 {
		b.header.ReceiptHash = EmptyRootHash
	} else {
		b.header.ReceiptHash = DeriveSha(Receipts(receipts), hasher)
	}

	return b
}

// NewBlockWithHeader creates a block with the given header data. The
// header data is copied, changes to header and to the field values
// will not affect the block.
func NewBlockWithHeader(header *Header) *Block {
	return &Block{header: CopyHeader(header)}
}

// CopyHeader creates a deep copy of a block header to prevent side effects from
// modifying a header variable.
func CopyHeader(h *Header) *Header {
	cpy := *h
	if cpy.Number = new(big.Int); h.Number != nil {
		cpy.Number.Set(h.Number)
	}
	if len(h.Extra) > 0 {
		cpy.Extra = make([]byte, len(h.Extra))
		copy(cpy.Extra, h.Extra)
	}

	return &cpy
}

// DecodeRLP decodes the Ethereum
func (b *Block) DecodeRLP(s *rlp.Stream) error {
	var eb extblock
	_, size, _ := s.Kind()
	if err := s.Decode(&eb); err != nil {
		return err
	}
	b.header, b.transactions = eb.Header, eb.Txs
	b.size.Store(common.StorageSize(rlp.ListSize(size)))
	return nil
}

// EncodeRLP serializes b into the Ethereum RLP block format.
func (b *Block) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, extblock{
		Header: b.header,
		Txs:    b.transactions,
	})
}

// [deprecated by eth/63]
func (b *StorageBlock) DecodeRLP(s *rlp.Stream) error {
	var sb storageblock
	if err := s.Decode(&sb); err != nil {
		return err
	}
	b.header, b.transactions, b.td = sb.Header, sb.Txs, sb.TD
	return nil
}

// TODO: copies

func (b *Block) Transactions() Transactions { return b.transactions }

func (b *Block) Transaction(hash common.Hash) *Transaction {
	for _, transaction := range b.transactions {
		if transaction.Hash() == hash {
			return transaction
		}
	}
	return nil
}

func (b *Block) Number() *big.Int     { return new(big.Int).Set(b.header.Number) }
func (b *Block) GasLimit() uint64     { return b.header.GasLimit }
func (b *Block) GasUsed() uint64      { return b.header.GasUsed }
func (b *Block) Difficulty() *big.Int { return b.header.Difficulty() }
func (b *Block) Time() uint64         { return b.header.Time }

func (b *Block) NumberU64() uint64        { return b.header.Number.Uint64() }
func (b *Block) Coinbase() common.Address { return b.header.Coinbase() }
func (b *Block) Root() common.Hash        { return b.header.Root }
func (b *Block) ParentHash() common.Hash  { return b.header.ParentHash }
func (b *Block) TxHash() common.Hash      { return b.header.TxHash }
func (b *Block) ReceiptHash() common.Hash { return b.header.ReceiptHash }
func (b *Block) Extra() []byte            { return common.CopyBytes(b.header.Extra) }

//---------------------------------------------------------------------------------------------
func (b *Block) KeyHash() common.Hash { return b.header.KeyHash }
func (b *Block) BlockType() uint8 {
	n := b.header.Number.Uint64()
	if n != 0 && n < params.ForkNewVerBlock && len(b.header.Extra) > ExtraKeyMinSize { //for old blockchain
		return Key_Block
	}
	return b.header.BlockType
}
func (b *Block) Signature() []byte  { return b.header.Signature }
func (b *Block) Exceptions() []byte { return b.header.Exceptions }

func (b *Block) Header() *Header { return CopyHeader(b.header) }

// Body returns the non-header content of the block.
func (b *Block) Body() *Body { return &Body{b.transactions} }

// Size returns the true RLP encoded storage size of the block, either by encoding
// and returning it, or returning a previsouly cached value.
func (b *Block) Size() common.StorageSize {
	if size := b.size.Load(); size != nil {
		return size.(common.StorageSize)
	}
	c := writeCounter(0)
	rlp.Encode(&c, b)
	b.size.Store(common.StorageSize(c))
	return common.StorageSize(c)
}

// SanityCheck can be used to prevent that unbounded fields are
// stuffed with junk data to add processing overhead
func (b *Block) SanityCheck() error {
	return b.header.SanityCheck()
}

type writeCounter common.StorageSize

func (c *writeCounter) Write(b []byte) (int, error) {
	*c += writeCounter(len(b))
	return len(b), nil
}

// WithSeal returns a new block with the data from b but the header replaced with
// the sealed one.
func (b *Block) WithSeal(header *Header) *Block {
	cpy := *header

	return &Block{
		header:       &cpy,
		transactions: b.transactions,
	}
}

// WithBody returns a new block with the given transaction and uncle contents.
func (b *Block) WithBody(transactions []*Transaction) *Block {
	block := &Block{
		header:       CopyHeader(b.header),
		transactions: make([]*Transaction, len(transactions)),
	}
	copy(block.transactions, transactions)
	return block
}

func (b *Block) CopyOrg() *Block {
	block := b.WithBody(b.Transactions())
	block.header.SetSignInfoNull()
	n := block.header.NumberU64()
	if n < params.ForkNewVerBlock && n != 0 && len(block.header.Extra) > ExtraKeyMinSize { //for old block
		block.header.Extra = []byte{}
	}
	return block
}

// Hash returns the keccak256 hash of b's header.
// The hash is computed on the first call and cached thereafter.
func (b *Block) Hash() common.Hash {
	if hash := b.hash.Load(); hash != nil {
		return hash.(common.Hash)
	}
	v := b.header.Hash()
	b.hash.Store(v)
	return v
}

func (b *Block) SetSignature(sig []byte, exceptions []byte) {
	b.header.Signature = sig
	b.header.Exceptions = exceptions
}

func (b *Block) SetKeyblock(keyblock *KeyBlock) {
	data := keyblock.EncodeToBytes()
	b.header.Extra = make([]byte, ExtraKeyOffset+len(data))
	copy(b.header.Extra[ExtraKeyOffset:], data)
}
func (b *Block) KeyInfo() []byte {
	if len(b.header.Extra) < ExtraKeyOffset {
		return nil
	}
	return b.header.Extra[ExtraKeyOffset:]
}

type Blocks []*Block

func (b *Block) EncodeToBytes() []byte {
	m := make([]byte, 0)
	buff := bytes.NewBuffer(m)
	err := b.EncodeRLP(buff)
	if err != nil {
		return nil
	}

	return buff.Bytes()
}

func DecodeToBlock(data []byte) *Block {
	block := &Block{}
	buff := bytes.NewBuffer(data)
	c := rlp.NewStream(buff, 0)
	err := block.DecodeRLP(c)
	if err != nil {
		return nil
	}
	return block
}
