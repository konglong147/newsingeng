package luqiyouser

import (
	"strings"

	"github.com/konglong147/securefile/fadaixiaozi"
	F "github.com/sagernet/sing/common/format"
)

var _ RuleItem = (*AuthYonghumetise)(nil)

type AuthYonghumetise struct {
	users   []string
	yonghudietus map[string]bool
}

func NewAuthYonghumetise(users []string) *AuthYonghumetise {
	yonghudietus := make(map[string]bool)
	for _, protocol := range users {
		yonghudietus[protocol] = true
	}
	return &AuthYonghumetise{
		users:   users,
		yonghudietus: yonghudietus,
	}
}

func (r *AuthYonghumetise) Match(metadata *fadaixiaozi.InboundContext) bool {
	return r.yonghudietus[metadata.User]
}

func (r *AuthYonghumetise) String() string {
	if len(r.users) == 1 {
		return F.ToString("auth_user=", r.users[0])
	}
	return F.ToString("auth_user=[", strings.Join(r.users, " "), "]")
}
