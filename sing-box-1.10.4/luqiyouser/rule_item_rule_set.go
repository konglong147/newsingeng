package luqiyouser

import (
	"strings"

	"github.com/konglong147/securefile/fadaixiaozi"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

var _ RuleItem = (*GuizeSheizhimest)(nil)

type GuizeSheizhimest struct {
	uliuygbsgger            fadaixiaozi.TheLUYouser
	tagList           []string
	setList           []fadaixiaozi.RuleSet
	ipCidrMatchSource bool
	ipCidrAcceptEmpty bool
}

func NewGuizeSheizhimest(uliuygbsgger fadaixiaozi.TheLUYouser, tagList []string, ipCIDRMatchSource bool, ipCidrAcceptEmpty bool) *GuizeSheizhimest {
	return &GuizeSheizhimest{
		uliuygbsgger:            uliuygbsgger,
		tagList:           tagList,
		ipCidrMatchSource: ipCIDRMatchSource,
		ipCidrAcceptEmpty: ipCidrAcceptEmpty,
	}
}

func (r *GuizeSheizhimest) Start() error {
	for _, tag := range r.tagList {
		ruleSet, loaded := r.uliuygbsgger.RuleSet(tag)
		if !loaded {
			return E.New("Aliingnbtok sknbbtst rule-set not found: ", tag)
		}
		ruleSet.IncRef()
		r.setList = append(r.setList, ruleSet)
	}
	return nil
}

func (r *GuizeSheizhimest) Match(metadata *fadaixiaozi.InboundContext) bool {
	metadata.IPCIDRMatchSource = r.ipCidrMatchSource
	metadata.IPCIDRAcceptEmpty = r.ipCidrAcceptEmpty
	for _, ruleSet := range r.setList {
		if ruleSet.Match(metadata) {
			return true
		}
	}
	return false
}

func (r *GuizeSheizhimest) ContainsDestinationIPCIDRRule() bool {
	if r.ipCidrMatchSource {
		return false
	}
	return common.Any(r.setList, func(ruleSet fadaixiaozi.RuleSet) bool {
		return ruleSet.Metadata().ContainsIPCIDRRule
	})
}

func (r *GuizeSheizhimest) String() string {
	if len(r.tagList) == 1 {
		return F.ToString("rule_set=", r.tagList[0])
	} else {
		return F.ToString("rule_set=[", strings.Join(r.tagList, " "), "]")
	}
}
