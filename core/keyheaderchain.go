package core

import (
	"math/big"
	"sync/atomic"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/params"
	lru "github.com/hashicorp/golang-lru"
)

type KeyHeaderChain struct {
	config *params.ChainConfig

	chainDb       ethdb.Database
	genesisHeader *types.KeyBlockHeader

	currentHeader     atomic.Value // Current head of the header chain (may be above the block chain!)
	currentHeaderHash common.Hash  // Hash of the current head of the header chain (prevent recomputing all the time)

	headerCache *lru.Cache // Cache for the most recent block headers
	tdCache     *lru.Cache // Cache for the most recent block total difficulties
	numberCache *lru.Cache // Cache for the most recent block numbers

	procInterrupt func() bool
}

func NewKeyHeaderChain(chainDb ethdb.Database, config *params.ChainConfig, procInterrupt func() bool) (*KeyHeaderChain, error) {
	headerCache, _ := lru.New(headerCacheLimit)
	tdCache, _ := lru.New(tdCacheLimit)
	numberCache, _ := lru.New(numberCacheLimit)

	khc := &KeyHeaderChain{
		config:        config,
		chainDb:       chainDb,
		headerCache:   headerCache,
		tdCache:       tdCache,
		numberCache:   numberCache,
		procInterrupt: procInterrupt,
	}

	khc.genesisHeader = khc.GetHeaderByNumber(0)
	if khc.genesisHeader == nil {
		return nil, ErrNoKeyGenesis
	}

	khc.currentHeader.Store(khc.genesisHeader)
	if head := rawdb.ReadHeadKeyBlockHash(chainDb); head != (common.Hash{}) {
		if chead := khc.GetHeaderByHash(head); chead != nil {
			khc.currentHeader.Store(chead)
		}
	}
	khc.currentHeaderHash = khc.CurrentHeader().Hash()

	return khc, nil
}

// GetHeaderByNumber retrieves a block header from the database by number,
// caching it (associated with its hash) if found.
func (khc *KeyHeaderChain) GetHeaderByNumber(number uint64) *types.KeyBlockHeader {
	hash := rawdb.ReadKeyBlockHash(khc.chainDb, number)
	if hash == (common.Hash{}) {
		return nil
	}
	return khc.GetHeader(hash, number)
}

// GetHeader retrieves a block header from the database by hash and number,
// caching it if found.
func (khc *KeyHeaderChain) GetHeader(hash common.Hash, number uint64) *types.KeyBlockHeader {
	// Short circuit if the header's already in the cache, retrieve otherwise
	if header, ok := khc.headerCache.Get(hash); ok {
		return header.(*types.KeyBlockHeader)
	}
	header := rawdb.ReadKeyHeader(khc.chainDb, hash, number)
	if header == nil {
		return nil
	}
	// Cache the found header for next time and return
	khc.headerCache.Add(hash, header)
	return header
}

// GetBlockNumber retrieves the block number belonging to the given hash
// from the cache or database
func (khc *KeyHeaderChain) GetBlockNumber(hash common.Hash) *uint64 {
	if cached, ok := khc.numberCache.Get(hash); ok {
		number := cached.(uint64)
		return &number
	}
	number := rawdb.ReadKeyHeaderNumber(khc.chainDb, hash)
	if number != nil {
		khc.numberCache.Add(hash, *number)
	}
	return number
}

// GetHeaderByHash retrieves a block header from the database by hash, caching it if
// found.
func (khc *KeyHeaderChain) GetHeaderByHash(hash common.Hash) *types.KeyBlockHeader {
	number := khc.GetBlockNumber(hash)
	if number == nil {
		return nil
	}
	return khc.GetHeader(hash, *number)
}

func (khc *KeyHeaderChain) CurrentHeader() *types.KeyBlockHeader {
	return khc.currentHeader.Load().(*types.KeyBlockHeader)
}

func (khc *KeyHeaderChain) SetCurrentHeader(head *types.KeyBlockHeader) {
	rawdb.WriteHeadKeyHeaderHash(khc.chainDb, head.Hash())

	khc.currentHeader.Store(head)
	khc.currentHeaderHash = head.Hash()
}

// GetTd retrieves a block's total difficulty in the canonical chain from the
// database by hash and number, caching it if found.
func (khc *KeyHeaderChain) GetTd(hash common.Hash, number uint64) *big.Int {
	// Short circuit if the td's already in the cache, retrieve otherwise
	if cached, ok := khc.tdCache.Get(hash); ok {
		return cached.(*big.Int)
	}
	td := rawdb.ReadTd(khc.chainDb, hash, number)
	if td == nil {
		return nil
	}
	// Cache the found body for next time and return
	khc.tdCache.Add(hash, td)
	return td
}

// SetGenesis sets a new genesis block header for the chain
func (khc *KeyHeaderChain) SetGenesis(head *types.KeyBlockHeader) {
	khc.genesisHeader = head
}

// WriteTd stores a block's total difficulty into the database, also caching it
// along the way.
func (khc *KeyHeaderChain) WriteTd(hash common.Hash, number uint64, td *big.Int) error {
	rawdb.WriteTd(khc.chainDb, hash, number, td)
	khc.tdCache.Add(hash, new(big.Int).Set(td))
	return nil
}
