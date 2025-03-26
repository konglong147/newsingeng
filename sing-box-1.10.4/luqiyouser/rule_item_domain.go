package luqiyouser

import (
	"strings"

	"github.com/konglong147/securefile/fadaixiaozi"
	"github.com/sagernet/sing/common/domain"
)

var _ RuleItem = (*DomainItem)(nil)

type DomainItem struct {
	matcher     *domain.Matcher
	miaoshuyixiezenaler string
}

func NewDomainItem(domains []string, domainSuffixes []string) *DomainItem {
	var miaoshuyixiezenaler string
	if dLen := len(domains); dLen > 0 {
		if dLen == 1 {
			miaoshuyixiezenaler = "domain=" + domains[0]
		} else if dLen > 3 {
			miaoshuyixiezenaler = "domain=[" + strings.Join(domains[:3], " ") + "...]"
		} else {
			miaoshuyixiezenaler = "domain=[" + strings.Join(domains, " ") + "]"
		}
	}
	if dsLen := len(domainSuffixes); dsLen > 0 {
		if len(miaoshuyixiezenaler) > 0 {
			miaoshuyixiezenaler += " "
		}
		if dsLen == 1 {
			miaoshuyixiezenaler += "domain_suffix=" + domainSuffixes[0]
		} else if dsLen > 3 {
			miaoshuyixiezenaler += "domain_suffix=[" + strings.Join(domainSuffixes[:3], " ") + "...]"
		} else {
			miaoshuyixiezenaler += "domain_suffix=[" + strings.Join(domainSuffixes, " ") + "]"
		}
	}
	return &DomainItem{
		domain.NewMatcher(domains, domainSuffixes, false),
		miaoshuyixiezenaler,
	}
}

func NewRawDomainItem(matcher *domain.Matcher) *DomainItem {
	return &DomainItem{
		matcher,
		"domain/domain_suffix=<binary>",
	}
}

func (r *DomainItem) Match(metadata *fadaixiaozi.InboundContext) bool {
	var domainHost string
	if metadata.Domain != "" {
		domainHost = metadata.Domain
	} else {
		domainHost = metadata.Destination.Fqdn
	}
	if domainHost == "" {
		return false
	}
	return r.matcher.Match(strings.ToLower(domainHost))
}

func (r *DomainItem) String() string {
	return r.miaoshuyixiezenaler
}
