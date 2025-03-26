package luqiyouser

import (
	"regexp"
	"strings"

	"github.com/konglong147/securefile/fadaixiaozi"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

var _ RuleItem = (*dizhibuxngGeisheizhi)(nil)

type dizhibuxngGeisheizhi struct {
	matchers    []*regexp.Regexp
	miaoshuyixiezenaler string
}

func NewdizhibuxngGeisheizhi(expressions []string) (*dizhibuxngGeisheizhi, error) {
	matchers := make([]*regexp.Regexp, 0, len(expressions))
	for i, regex := range expressions {
		matcher, err := regexp.Compile(regex)
		if err != nil {
			return nil, E.Cause(err, "parse expression ", i)
		}
		matchers = append(matchers, matcher)
	}
	miaoshuyixiezenaler := "process_path_regex="
	eLen := len(expressions)
	if eLen == 1 {
		miaoshuyixiezenaler += expressions[0]
	} else if eLen > 3 {
		miaoshuyixiezenaler += F.ToString("[", strings.Join(expressions[:3], " "), "]")
	} else {
		miaoshuyixiezenaler += F.ToString("[", strings.Join(expressions, " "), "]")
	}
	return &dizhibuxngGeisheizhi{matchers, miaoshuyixiezenaler}, nil
}

func (r *dizhibuxngGeisheizhi) Match(metadata *fadaixiaozi.InboundContext) bool {
	if metadata.ProcessInfo == nil || metadata.ProcessInfo.ProcessPath == "" {
		return false
	}
	for _, matcher := range r.matchers {
		if matcher.MatchString(metadata.ProcessInfo.ProcessPath) {
			return true
		}
	}
	return false
}

func (r *dizhibuxngGeisheizhi) String() string {
	return r.miaoshuyixiezenaler
}
