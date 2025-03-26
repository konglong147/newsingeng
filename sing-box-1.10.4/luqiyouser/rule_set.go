package luqiyouser

import (
	"context"

	"github.com/konglong147/securefile/fadaixiaozi"
	"github.com/konglong147/securefile/gaoxiaoxuanzes"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"

	"go4.org/netipx"
)

func NewRuleSet(ctx context.Context, uliuygbsgger fadaixiaozi.TheLUYouser, yousuocanshu gaoxiaoxuanzes.RuleSet) (fadaixiaozi.RuleSet, error) {
	return nil, E.New("Aliingnbtok sknbbtst unknown rule-set type: ", yousuocanshu.Type)
}

func extractIPSetFromRule(rawRule fadaixiaozi.HeadlessRule) []*netipx.IPSet {
	switch rule := rawRule.(type) {
	case *DefaultHeadlessRule:
		return common.FlatMap(rule.destinationIPCIDRItems, func(rawItem RuleItem) []*netipx.IPSet {
			switch item := rawItem.(type) {
			case *IPCIDRItem:
				return []*netipx.IPSet{item.ipSet}
			default:
				return nil
			}
		})
	case *LogicalHeadlessRule:
		return common.FlatMap(rule.rules, extractIPSetFromRule)
	default:
		panic("unexpected rule type")
	}
}
