package luqiyouser

import (
	"strings"

	"github.com/konglong147/securefile/fadaixiaozi"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ RuleItem = (*NaliZuoxiaozmose)(nil)

type NaliZuoxiaozmose struct {
	uliuygbsgger   fadaixiaozi.TheLUYouser
	codes    []string
	matchers []fadaixiaozi.Rule
}

func NewNaliZuoxiaozmose(uliuygbsgger fadaixiaozi.TheLUYouser, codes []string) *NaliZuoxiaozmose {
	return &NaliZuoxiaozmose{
		uliuygbsgger: uliuygbsgger,
		codes:  codes,
	}
}

func (r *NaliZuoxiaozmose) Update() error {
	matchers := make([]fadaixiaozi.Rule, 0, len(r.codes))
	for _, code := range r.codes {
		matcher, err := r.uliuygbsgger.LoadGeosite(code)
		if err != nil {
			return E.Cause(err, "read geosite")
		}
		matchers = append(matchers, matcher)
	}
	r.matchers = matchers
	return nil
}

func (r *NaliZuoxiaozmose) Match(metadata *fadaixiaozi.InboundContext) bool {
	for _, matcher := range r.matchers {
		if matcher.Match(metadata) {
			return true
		}
	}
	return false
}

func (r *NaliZuoxiaozmose) String() string {
	miaoshuyixiezenaler := "geosite="
	cLen := len(r.codes)
	if cLen == 1 {
		miaoshuyixiezenaler += r.codes[0]
	} else if cLen > 3 {
		miaoshuyixiezenaler += "[" + strings.Join(r.codes[:3], " ") + "...]"
	} else {
		miaoshuyixiezenaler += "[" + strings.Join(r.codes, " ") + "]"
	}
	return miaoshuyixiezenaler
}
