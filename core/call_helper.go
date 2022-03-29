package core

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/consensus/ethash"
	"github.com/cypherium/cypher/core/rawdb"
	"github.com/cypherium/cypher/core/state"
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/core/vm"
	"github.com/cypherium/cypher/crypto"
	"github.com/cypherium/cypher/ethdb"
	"github.com/cypherium/cypher/params"
)

// callHelper makes it easier to do proper calls and use the state transition object.
// It also manages the nonces of the caller and keeps private and public state, which
// can be freely modified outside of the helper.
type callHelper struct {
	db ethdb.Database

	nonces map[common.Address]uint64
	header types.Header
	gp     *GasPool

	PrivateState, PublicState *state.StateDB
}

// TxNonce returns the pending nonce
func (cg *callHelper) TxNonce(addr common.Address) uint64 {
	return cg.nonces[addr]
}

// MakeCall makes does a call to the recipient using the given input. It can switch between private and public
// by setting the private boolean flag. It returns an error if the call failed.
func (cg *callHelper) MakeCall(private bool, key *ecdsa.PrivateKey, to common.Address, input []byte) error {
	var (
		from = crypto.PubkeyToAddress(key.PublicKey)
		err  error
	)

	// TODO(joel): these are just stubbed to the same values as in dual_state_test.go
	cg.header.Number = new(big.Int)
	cg.header.Time = uint64(43)
	cg.header.Difficulty = new(big.Int).SetUint64(1000488)
	cg.header.GasLimit = 4700000

	signer := types.MakeSigner(params.CypherTestChainConfig, cg.header.Number)
	tx, err := types.SignTx(types.NewTransaction(cg.TxNonce(from), to, new(big.Int), 1000000, new(big.Int), input), signer, key)

	if err != nil {
		return err
	}
	defer func() { cg.nonces[from]++ }()
	msg, err := tx.AsMessage(signer)
	if err != nil {
		return err
	}

	publicState := cg.PublicState
	// TODO(joel): can we just pass nil instead of bc?
	bc, _ := NewBlockChain(cg.db, nil, params.CypherTestChainConfig, ethash.NewFaker(), vm.Config{}, nil, nil, nil)
	context := NewEVMContext(msg, &cg.header, bc, &from)
	vmenv := vm.NewEVM(context, publicState, params.CypherTestChainConfig, vm.Config{})
	sender := vm.AccountRef(msg.From())
	vmenv.Call(sender, to, msg.Data(), 100000000, new(big.Int))
	return err
}

// MakeCallHelper returns a new callHelper
func MakeCallHelper() *callHelper {
	memdb := rawdb.NewMemoryDatabase()
	db := state.NewDatabase(memdb)

	publicState, err := state.New(common.Hash{}, db, nil)
	if err != nil {
		panic(err)
	}
	privateState, err := state.New(common.Hash{}, db, nil)
	if err != nil {
		panic(err)
	}
	cg := &callHelper{
		db:           memdb,
		nonces:       make(map[common.Address]uint64),
		gp:           new(GasPool).AddGas(5000000),
		PublicState:  publicState,
		PrivateState: privateState,
	}
	return cg
}
