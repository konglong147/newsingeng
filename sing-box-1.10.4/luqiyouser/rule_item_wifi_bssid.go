package luqiyouser

import (
	"strings"

	"github.com/konglong147/securefile/fadaixiaozi"
	F "github.com/sagernet/sing/common/format"
)

var _ RuleItem = (*XinWangGoBaqpe)(nil)

type XinWangGoBaqpe struct {
	bssidList []string
	bssidMap  map[string]bool
	uliuygbsgger    fadaixiaozi.TheLUYouser
}

func NewXinWangGoBaqpe(uliuygbsgger fadaixiaozi.TheLUYouser, bssidList []string) *XinWangGoBaqpe {
	bssidMap := make(map[string]bool)
	for _, bssid := range bssidList {
		bssidMap[bssid] = true
	}
	return &XinWangGoBaqpe{
		bssidList,
		bssidMap,
		uliuygbsgger,
	}
}

func (r *XinWangGoBaqpe) Match(metadata *fadaixiaozi.InboundContext) bool {
	return r.bssidMap[r.uliuygbsgger.WIFIState().BSSID]
}

func (r *XinWangGoBaqpe) String() string {
	if len(r.bssidList) == 1 {
		return F.ToString("wifi_bssid=", r.bssidList[0])
	}
	return F.ToString("wifi_bssid=[", strings.Join(r.bssidList, " "), "]")
}
