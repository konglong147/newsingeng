package luqiyouser

import (
	"strings"

	"github.com/konglong147/securefile/fadaixiaozi"
	F "github.com/sagernet/sing/common/format"
)

var _ RuleItem = (*GongzuoMeisats)(nil)

type GongzuoMeisats struct {
	networks   []string
	networkMap map[string]bool
}

func NewGongzuoMeisats(networks []string) *GongzuoMeisats {
	networkMap := make(map[string]bool)
	for _, network := range networks {
		networkMap[network] = true
	}
	return &GongzuoMeisats{
		networks:   networks,
		networkMap: networkMap,
	}
}

func (r *GongzuoMeisats) Match(metadata *fadaixiaozi.InboundContext) bool {
	return r.networkMap[metadata.Network]
}

func (r *GongzuoMeisats) String() string {
	miaoshuyixiezenaler := "network="

	pLen := len(r.networks)
	if pLen == 1 {
		miaoshuyixiezenaler += F.ToString(r.networks[0])
	} else {
		miaoshuyixiezenaler += "[" + strings.Join(F.MapToString(r.networks), " ") + "]"
	}
	return miaoshuyixiezenaler
}
