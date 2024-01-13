package core

import (
	"github.com/cypherium/cypher/core/types"
	"github.com/cypherium/cypher/params"
)

type KeyBlockValidator struct {
	config *params.ChainConfig // Chain configuration options
	kbc    *KeyBlockChain      // Canonical block chain
}

// NewBlockValidator returns a new block validator which is safe for re-use
func NewKeyBlockValidator(config *params.ChainConfig, blockchain *KeyBlockChain) *KeyBlockValidator {
	validator := &KeyBlockValidator{
		config: config,
		kbc:    blockchain,
	}
	return validator
}

//ValidateKeyBlock,verify new keyblock
//All node rotations:1.Normal reconfig,witness=prvCommittee+new leader(input[0]);2.viewchange ,witness=prvCommittee
//2f+1 fixed，f node rotations:1.Normal reconfig,witness=prvCommittee;2.viewchange ,witness=prvCommittee
//Manual reconfig:witness= input
func (kbv *KeyBlockValidator) ValidateKeyBlock(block *types.KeyBlock) error {
	blockNumber := block.NumberU64()
	if kbv.kbc.HasBlock(block.Hash(), blockNumber) {
		return types.ErrKnownBlock
	}

	if !kbv.kbc.HasBlock(block.ParentHash(), blockNumber-1) {
		return types.ErrUnknownAncestor
	}
	/*
		//TxHash  verify
		mycommittee := &bftview.Committee{List: kbv.kbc.GetCommitteeByNumber(blockNumber - 1)}
		if mycommittee == nil || len(mycommittee.List) < 2 {
			return types.ErrInvalidCommittee
		}
		pubs := mycommittee.ToBlsPublicKeys(block.ParentHash())

		tmpBlock := block.CopyMe(nil, nil)
		m := make([]byte, 0)
		buff := bytes.NewBuffer(m)
		err := tmpBlock.EncodeRLP(buff)
		if err != nil {
			return err
		}
		//log.Info("key block", "Signatrue", block.Signatrue(), "exceptions", block.Exceptions(), "Bytes", buff.Bytes(), "pub", pubs)
		if !hotstuff.VerifySignature(block.Signatrue(), block.Exceptions(), buff.Bytes(), pubs, (len(pubs)+1)*2/3) {
			return types.ErrInvalidSignature
		}
	*/
	return nil
}
