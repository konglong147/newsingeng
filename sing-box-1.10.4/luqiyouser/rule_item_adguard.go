package luqiyouser

import (
	"strings"

	"github.com/konglong147/securefile/fadaixiaozi"
	"github.com/sagernet/sing/common/domain"
)

var _ RuleItem = (*AdGuardDomainItem)(nil)

type AdGuardDomainItem struct {
	matcher *domain.AdGuardMatcher
}

func NewAdGuardDomainItem(ruleLines []string) *AdGuardDomainItem {
	return &AdGuardDomainItem{
		domain.NewAdGuardMatcher(ruleLines),
	}
}

func NewRawAdGuardDomainItem(matcher *domain.AdGuardMatcher) *AdGuardDomainItem {
	return &AdGuardDomainItem{
		matcher,
	}
}

func (r *AdGuardDomainItem) Match(metadata *fadaixiaozi.InboundContext) bool {
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

func (r *AdGuardDomainItem) String() string {
	return "!adguard_domain_rules=<binary>"
}
