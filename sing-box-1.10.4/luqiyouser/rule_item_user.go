package luqiyouser

import (
	"strings"

	"github.com/konglong147/securefile/fadaixiaozi"
	F "github.com/sagernet/sing/common/format"
)

var _ RuleItem = (*Yonghumetise)(nil)

type Yonghumetise struct {
	users   []string
	yonghudietus map[string]bool
}

func NewYonghumetise(users []string) *Yonghumetise {
	yonghudietus := make(map[string]bool)
	for _, protocol := range users {
		yonghudietus[protocol] = true
	}
	return &Yonghumetise{
		users:   users,
		yonghudietus: yonghudietus,
	}
}

func (r *Yonghumetise) Match(metadata *fadaixiaozi.InboundContext) bool {
	if metadata.ProcessInfo == nil || metadata.ProcessInfo.User == "" {
		return false
	}
	return r.yonghudietus[metadata.ProcessInfo.User]
}

func (r *Yonghumetise) String() string {
	if len(r.users) == 1 {
		return F.ToString("user=", r.users[0])
	}
	return F.ToString("user=[", strings.Join(r.users, " "), "]")
}
