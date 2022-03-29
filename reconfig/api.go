package reconfig

import (
	"context"

	"github.com/cypherium/cypher/common"
	"github.com/cypherium/cypher/reconfig/bftview"
	"github.com/cypherium/cypher/rpc"
)

type PublicReconfigAPI struct {
	reconfig *ReconfigBackend
}

func NewPublicReconfigAPI(reconfig *ReconfigBackend) *PublicReconfigAPI {
	return &PublicReconfigAPI{reconfig}
}

func (s *PublicReconfigAPI) Role() string {
	i := bftview.IamMember()
	rs := ""
	if i >= 0 {
		if i == 0 {
			rs += "I'm leader."
		} else {
			rs += "I'm committee member."
		}
	} else {
		rs += "I'm common node."
	}
	return rs
}

func (s *PublicReconfigAPI) Leader() *common.Cnode {
	mb := bftview.GetCurrentMember()
	if mb != nil && len(mb.List) > 0 {
		return mb.List[0]
	}
	return nil
}
func (s *PublicReconfigAPI) RoleList() []*common.Cnode {
	mb := bftview.GetCurrentMember()
	if mb != nil {
		return mb.List
	}
	return nil
}

func (s *PublicReconfigAPI) Id(enodeId string) string {
	coinbase := bftview.GetServerCoinBase()
	return bftview.GetServerInfo(bftview.PublicKey) + "\n" + coinbase.String()
}

func (s *PublicReconfigAPI) Members(ctx context.Context, blockNr rpc.BlockNumber) ([]*common.Cnode, error) {
	if blockNr == rpc.LatestBlockNumber {
		return s.reconfig.KeyBlockChain().CurrentCommittee(), nil
	}
	return s.reconfig.KeyBlockChain().GetCommitteeByNumber(uint64(blockNr)), nil
}

func (s *PublicReconfigAPI) Exceptions(ctx context.Context, blockNr rpc.BlockNumber) []string {
	return s.reconfig.Exceptions(int64(blockNr))
}

func (s *PublicReconfigAPI) takePartInBlocks(ctx context.Context, addr common.Address, blockNr rpc.BlockNumber) []string {
	return s.reconfig.service.TakePartInBlocks(addr, int64(blockNr))
}
