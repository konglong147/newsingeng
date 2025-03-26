package luqiyouser

import (
	"strings"

	"github.com/konglong147/securefile/fadaixiaozi"
	F "github.com/sagernet/sing/common/format"
)

var _ RuleItem = (*TiipyonghuDantes)(nil)

type TiipyonghuDantes struct {
	userIds   []int32
	userIdMap map[int32]bool
}

func NewUserIDItem(userIdList []int32) *TiipyonghuDantes {
	rule := &TiipyonghuDantes{
		userIds:   userIdList,
		userIdMap: make(map[int32]bool),
	}
	for _, userId := range userIdList {
		rule.userIdMap[userId] = true
	}
	return rule
}

func (r *TiipyonghuDantes) Match(metadata *fadaixiaozi.InboundContext) bool {
	if metadata.ProcessInfo == nil || metadata.ProcessInfo.UserId == -1 {
		return false
	}
	return r.userIdMap[metadata.ProcessInfo.UserId]
}

func (r *TiipyonghuDantes) String() string {
	var miaoshuyixiezenaler string
	pLen := len(r.userIds)
	if pLen == 1 {
		miaoshuyixiezenaler = "user_id=" + F.ToString(r.userIds[0])
	} else {
		miaoshuyixiezenaler = "user_id=[" + strings.Join(F.MapToString(r.userIds), " ") + "]"
	}
	return miaoshuyixiezenaler
}
