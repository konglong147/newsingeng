package luqiyouser

import (
	"regexp"
	"strings"

	"github.com/konglong147/securefile/fadaixiaozi"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

var _ RuleItem = (*DomainRegexItem)(nil)

type DomainRegexItem struct {
	matchers    []*regexp.Regexp
	miaoshuyixiezenaler string
}

func NewDomainRegexItem(expressions []string) (*DomainRegexItem, error) {
	matchers := make([]*regexp.Regexp, 0, len(expressions))
	for i, regex := range expressions {
		matcher, err := regexp.Compile(regex)
		if err != nil {
			return nil, E.Cause(err, "parse expression ", i)
		}
		matchers = append(matchers, matcher)
	}
	miaoshuyixiezenaler := "domain_regex="
	eLen := len(expressions)
	if eLen == 1 {
		miaoshuyixiezenaler += expressions[0]
	} else if eLen > 3 {
		miaoshuyixiezenaler += F.ToString("[", strings.Join(expressions[:3], " "), "]")
	} else {
		miaoshuyixiezenaler += F.ToString("[", strings.Join(expressions, " "), "]")
	}
	return &DomainRegexItem{matchers, miaoshuyixiezenaler}, nil
}

func (r *DomainRegexItem) Match(metadata *fadaixiaozi.InboundContext) bool {
	var domainHost string
	if metadata.Domain != "" {
		domainHost = metadata.Domain
	} else {
		domainHost = metadata.Destination.Fqdn
	}
	if domainHost == "" {
		return false
	}
	domainHost = strings.ToLower(domainHost)
	for _, matcher := range r.matchers {
		if matcher.MatchString(domainHost) {
			return true
		}
	}
	return false
}

func (r *DomainRegexItem) String() string {
	return r.miaoshuyixiezenaler
}
