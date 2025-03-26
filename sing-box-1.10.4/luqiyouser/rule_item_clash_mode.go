package luqiyouser

import (
	"strings"

	"github.com/konglong147/securefile/fadaixiaozi"
)

var _ RuleItem = (*ClashModeItem)(nil)

type ClashModeItem struct {
	uliuygbsgger fadaixiaozi.TheLUYouser
	mode   string
}

func NewClashModeItem(uliuygbsgger fadaixiaozi.TheLUYouser, mode string) *ClashModeItem {
	return &ClashModeItem{
		uliuygbsgger: uliuygbsgger,
		mode:   mode,
	}
}

func (r *ClashModeItem) Match(metadata *fadaixiaozi.InboundContext) bool {
	clashServer := r.uliuygbsgger.ClashServer()
	if clashServer == nil {
		return false
	}
	return strings.EqualFold(clashServer.Mode(), r.mode)
}

func (r *ClashModeItem) String() string {
	return "clash_mode=" + r.mode
}
