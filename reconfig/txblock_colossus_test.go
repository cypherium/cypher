package reconfig

import (
	"math/big"
	"strings"
	"testing"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus/ethash"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/trie"
)

func newNormalBlockForPowTest(difficulty int64) *types.Block {
	header := &types.Header{
		ParentHash:  common.HexToHash("0x1"),
		UncleHash:   types.EmptyUncleHash,
		Coinbase:    common.HexToAddress("0x1234"),
		Root:        common.HexToHash("0x2"),
		TxHash:      common.HexToHash("0x3"),
		ReceiptHash: common.HexToHash("0x4"),
		Difficulty:  big.NewInt(difficulty),
		Number:      big.NewInt(1),
		GasLimit:    10000000,
		GasUsed:     21000,
		Time:        1,
		BlockType:   types.Normal_Block,
		KeyHash:     common.HexToHash("0x5"),
	}
	return types.NewBlock(header, nil, nil, nil, new(trie.Trie))
}

func TestSealNormalBlockSetsPowFields(t *testing.T) {
	txS := &txService{cph: &ReconfigBackend{engine: ethash.NewTester()}}
	block := newNormalBlockForPowTest(65536)

	var err error
	block, err = txS.sealNormalBlock(block)
	if err != nil {
		t.Fatalf("sealNormalBlock failed: %v", err)
	}
	if block.MixDigest() == (common.Hash{}) {
		t.Fatalf("expected non-empty MixDigest")
	}
	if err := txS.verifyNormalBlockSeal(block); err != nil {
		t.Fatalf("sealed block should verify: %v", err)
	}
}

func TestVerifyTxBlockRejectsInvalidMixDigest(t *testing.T) {
	txS := &txService{cph: &ReconfigBackend{engine: ethash.NewTester()}}
	block := newNormalBlockForPowTest(1024)
	var err error
	block, err = txS.sealNormalBlock(block)
	if err != nil {
		t.Fatalf("sealNormalBlock failed: %v", err)
	}
	header := block.Header()
	header.MixDigest = common.HexToHash("0xdeadbeef")
	block = block.WithSeal(header)

	if err := txS.verifyNormalBlockSeal(block); err == nil {
		t.Fatalf("expected verifyNormalBlockSeal to fail for invalid mix digest")
	}
}

func TestVerifyTxBlockRejectsInvalidNonce(t *testing.T) {
	txS := &txService{cph: &ReconfigBackend{engine: ethash.NewTester()}}
	block := newNormalBlockForPowTest(1024)
	var err error
	block, err = txS.sealNormalBlock(block)
	if err != nil {
		t.Fatalf("sealNormalBlock failed: %v", err)
	}
	header := block.Header()
	header.Nonce = types.EncodeNonce(header.Nonce.Uint64() + 1)
	block = block.WithSeal(header)

	if err := txS.verifyNormalBlockSeal(block); err == nil {
		t.Fatalf("expected verifyNormalBlockSeal to fail for invalid nonce")
	}
}

func TestDecideNewBlockRefusesInvalidNormalBlockBeforeInsert(t *testing.T) {
	txS := &txService{cph: &ReconfigBackend{engine: ethash.NewTester()}}
	block := newNormalBlockForPowTest(1024)
	// Leave block unsealed to trigger the explicit commit-time guard.
	err := txS.decideNewBlock(block, nil, nil)
	if err == nil {
		t.Fatalf("expected decideNewBlock to reject unsealed normal block")
	}
	if !strings.Contains(err.Error(), "refuse normal block before insert") {
		t.Fatalf("unexpected error: %v", err)
	}
}
