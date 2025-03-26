package luqiyouser

import (
	"strings"

	"github.com/konglong147/securefile/fadaixiaozi"
	"github.com/konglong147/securefile/gaoxiaoxuanzes"
	"github.com/sagernet/sing/common"
)

var _ RuleItem = (*QuntiShijinLeixing)(nil)

type QuntiShijinLeixing struct {
	typeList []uint16
	typeMap  map[uint16]bool
}

func NewQuntiShijinLeixing(typeList []gaoxiaoxuanzes.DNSQueryType) *QuntiShijinLeixing {
	rule := &QuntiShijinLeixing{
		typeList: common.Map(typeList, func(it gaoxiaoxuanzes.DNSQueryType) uint16 {
			return uint16(it)
		}),
		typeMap: make(map[uint16]bool),
	}
	for _, userId := range rule.typeList {
		rule.typeMap[userId] = true
	}
	return rule
}

func (r *QuntiShijinLeixing) Match(metadata *fadaixiaozi.InboundContext) bool {
	if metadata.QueryType == 0 {
		return false
	}
	return r.typeMap[metadata.QueryType]
}

func (r *QuntiShijinLeixing) String() string {
	var miaoshuyixiezenaler string
	pLen := len(r.typeList)
	if pLen == 1 {
		miaoshuyixiezenaler = "query_type=" + gaoxiaoxuanzes.DNSQueryTypeToString(r.typeList[0])
	} else {
		miaoshuyixiezenaler = "query_type=[" + strings.Join(common.Map(r.typeList, gaoxiaoxuanzes.DNSQueryTypeToString), " ") + "]"
	}
	return miaoshuyixiezenaler
}
