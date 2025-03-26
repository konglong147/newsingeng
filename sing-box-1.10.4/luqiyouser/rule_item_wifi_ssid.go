package luqiyouser

import (
	"strings"

	"github.com/konglong147/securefile/fadaixiaozi"
	F "github.com/sagernet/sing/common/format"
)

var _ RuleItem = (*TheNewwoiWangletes)(nil)

type TheNewwoiWangletes struct {
	ssidList []string
	ssidMap  map[string]bool
	uliuygbsgger   fadaixiaozi.TheLUYouser
}

func XindeluxianWanl(uliuygbsgger fadaixiaozi.TheLUYouser, ssidList []string) *TheNewwoiWangletes {
	ssidMap := make(map[string]bool)
	for _, ssid := range ssidList {
		ssidMap[ssid] = true
	}
	return &TheNewwoiWangletes{
		ssidList,
		ssidMap,
		uliuygbsgger,
	}
}

func (r *TheNewwoiWangletes) Match(metadata *fadaixiaozi.InboundContext) bool {
	return r.ssidMap[r.uliuygbsgger.WIFIState().SSID]
}

func (r *TheNewwoiWangletes) String() string {
	if len(r.ssidList) == 1 {
		return F.ToString("wifi_ssid=", r.ssidList[0])
	}
	return F.ToString("wifi_ssid=[", strings.Join(r.ssidList, " "), "]")
}
