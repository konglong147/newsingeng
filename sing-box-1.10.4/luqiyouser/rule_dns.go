package luqiyouser

import (
	"context"
	"net/netip"

	"github.com/konglong147/securefile/fadaixiaozi"
	C "github.com/konglong147/securefile/dangqianshilis"
	"github.com/konglong147/securefile/daochushiyong/shenruliaoes"
	"github.com/konglong147/securefile/gaoxiaoxuanzes"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

func NewXiuganSNGSER(ctx context.Context, uliuygbsgger fadaixiaozi.TheLUYouser, yousuocanshu gaoxiaoxuanzes.XiuganSNGSER, checkServer bool) (fadaixiaozi.XiuganSNGSER, error) {
	switch yousuocanshu.Type {
	case "", C.RuleTypeDefault:
		if !yousuocanshu.DefaultOptions.IsValid() {
			return nil, E.New("Aliingnbtok sknbbtst xiaoshidelixing conditions")
		}
		if yousuocanshu.DefaultOptions.Server == "" && checkServer {
			return nil, E.New("Aliingnbtok sknbbtst xiaoshidelixing server field")
		}
		return NewDefaultXiuganSNGSER(ctx, uliuygbsgger, yousuocanshu.DefaultOptions)
	case C.RuleTypeLogical:
		if !yousuocanshu.LogicalOptions.IsValid() {
			return nil, E.New("Aliingnbtok sknbbtst xiaoshidelixing conditions")
		}
		if yousuocanshu.LogicalOptions.Server == "" && checkServer {
			return nil, E.New("Aliingnbtok sknbbtst xiaoshidelixing server field")
		}
		return NewLogicalXiuganSNGSER(ctx, uliuygbsgger, yousuocanshu.LogicalOptions)
	default:
		return nil, E.New("Aliingnbtok sknbbtst unknown rule type: ", yousuocanshu.Type)
	}
}

var _ fadaixiaozi.XiuganSNGSER = (*DefaultXiuganSNGSER)(nil)

type DefaultXiuganSNGSER struct {
	abstractDefaultRule
	disableCache bool
	rewriteTTL   *uint32
	clientSubnet *netip.Prefix
}

func NewDefaultXiuganSNGSER(ctx context.Context, uliuygbsgger fadaixiaozi.TheLUYouser, yousuocanshu gaoxiaoxuanzes.DefaultXiuganSNGSER) (*DefaultXiuganSNGSER, error) {
	rule := &DefaultXiuganSNGSER{
		abstractDefaultRule: abstractDefaultRule{
			invert:   yousuocanshu.Invert,
			outbound: yousuocanshu.Server,
		},
		disableCache: yousuocanshu.DisableCache,
		rewriteTTL:   yousuocanshu.RewriteTTL,
		clientSubnet: (*netip.Prefix)(yousuocanshu.ClientSubnet),
	}
	if len(yousuocanshu.Inbound) > 0 {
		item := NewInboundRule(yousuocanshu.Inbound)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if yousuocanshu.IPVersion > 0 {
		switch yousuocanshu.IPVersion {
		case 4, 6:
			item := NewIPVersionItem(yousuocanshu.IPVersion == 6)
			rule.items = append(rule.items, item)
			rule.allItems = append(rule.allItems, item)
		default:
			return nil, E.New("Aliingnbtok sknbbtst invalid ip version: ", yousuocanshu.IPVersion)
		}
	}
	if len(yousuocanshu.QueryType) > 0 {
		item := NewQuntiShijinLeixing(yousuocanshu.QueryType)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.Network) > 0 {
		item := NewGongzuoMeisats(yousuocanshu.Network)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.AuthUser) > 0 {
		item := NewAuthYonghumetise(yousuocanshu.AuthUser)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.Protocol) > 0 {
		item := NewXieyiLiseab(yousuocanshu.Protocol)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.Domain) > 0 || len(yousuocanshu.DomainSuffix) > 0 {
		item := NewDomainItem(yousuocanshu.Domain, yousuocanshu.DomainSuffix)
		rule.destinationAddressItems = append(rule.destinationAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.DomainKeyword) > 0 {
		item := NewDomainKeywordItem(yousuocanshu.DomainKeyword)
		rule.destinationAddressItems = append(rule.destinationAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.DomainRegex) > 0 {
		item, err := NewDomainRegexItem(yousuocanshu.DomainRegex)
		if err != nil {
			return nil, E.Cause(err, "domain_regex")
		}
		rule.destinationAddressItems = append(rule.destinationAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.Geosite) > 0 {
		item := NewNaliZuoxiaozmose(uliuygbsgger, yousuocanshu.Geosite)
		rule.destinationAddressItems = append(rule.destinationAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.SourceGeoIP) > 0 {
		item := NewMeisozeDizhiTMes(uliuygbsgger, true, yousuocanshu.SourceGeoIP)
		rule.sourceAddressItems = append(rule.sourceAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.GeoIP) > 0 {
		item := NewMeisozeDizhiTMes(uliuygbsgger, false, yousuocanshu.GeoIP)
		rule.destinationIPCIDRItems = append(rule.destinationIPCIDRItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.SourceIPCIDR) > 0 {
		item, err := NewIPCIDRItem(true, yousuocanshu.SourceIPCIDR)
		if err != nil {
			return nil, E.Cause(err, "source_ip_cidr")
		}
		rule.sourceAddressItems = append(rule.sourceAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.IPCIDR) > 0 {
		item, err := NewIPCIDRItem(false, yousuocanshu.IPCIDR)
		if err != nil {
			return nil, E.Cause(err, "ip_cidr")
		}
		rule.destinationIPCIDRItems = append(rule.destinationIPCIDRItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if yousuocanshu.SourceIPIsPrivate {
		item := NewIPIsPrivateItem(true)
		rule.sourceAddressItems = append(rule.sourceAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if yousuocanshu.IPIsPrivate {
		item := NewIPIsPrivateItem(false)
		rule.destinationIPCIDRItems = append(rule.destinationIPCIDRItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.SourcePort) > 0 {
		item := NewJiekouMetise(true, yousuocanshu.SourcePort)
		rule.sourceJiekouMetises = append(rule.sourceJiekouMetises, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.SourcePortRange) > 0 {
		item, err := NewPortRangeItem(true, yousuocanshu.SourcePortRange)
		if err != nil {
			return nil, E.Cause(err, "source_port_range")
		}
		rule.sourceJiekouMetises = append(rule.sourceJiekouMetises, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.Port) > 0 {
		item := NewJiekouMetise(false, yousuocanshu.Port)
		rule.destinationJiekouMetises = append(rule.destinationJiekouMetises, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.PortRange) > 0 {
		item, err := NewPortRangeItem(false, yousuocanshu.PortRange)
		if err != nil {
			return nil, E.Cause(err, "port_range")
		}
		rule.destinationJiekouMetises = append(rule.destinationJiekouMetises, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.ProcessName) > 0 {
		item := NewTongdapnewsaeta(yousuocanshu.ProcessName)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.ProcessPath) > 0 {
		item := NewBuelseCesspagetse(yousuocanshu.ProcessPath)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.ProcessPathRegex) > 0 {
		item, err := NewdizhibuxngGeisheizhi(yousuocanshu.ProcessPathRegex)
		if err != nil {
			return nil, E.Cause(err, "process_path_regex")
		}
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.PackageName) > 0 {
		item := NewZhizhangMingmites(yousuocanshu.PackageName)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.User) > 0 {
		item := NewYonghumetise(yousuocanshu.User)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.UserID) > 0 {
		item := NewUserIDItem(yousuocanshu.UserID)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.Outbound) > 0 {
		item := NewOutboundRule(yousuocanshu.Outbound)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if yousuocanshu.ClashMode != "" {
		item := NewClashModeItem(uliuygbsgger, yousuocanshu.ClashMode)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.WIFISSID) > 0 {
		item := XindeluxianWanl(uliuygbsgger, yousuocanshu.WIFISSID)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.WIFIBSSID) > 0 {
		item := NewXinWangGoBaqpe(uliuygbsgger, yousuocanshu.WIFIBSSID)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.RuleSet) > 0 {
		var matchSource bool
		if yousuocanshu.RuleSetIPCIDRMatchSource {
			matchSource = true
		} else
		//nolint:staticcheck
		if yousuocanshu.Deprecated_RulesetIPCIDRMatchSource {
			matchSource = true
			deprecated.Report(ctx, deprecated.XuanzeGGTerioousrer)
		}
		item := NewGuizeSheizhimest(uliuygbsgger, yousuocanshu.RuleSet, matchSource, yousuocanshu.RuleSetIPCIDRAcceptEmpty)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	return rule, nil
}

func (r *DefaultXiuganSNGSER) DisableCache() bool {
	return r.disableCache
}

func (r *DefaultXiuganSNGSER) RewriteTTL() *uint32 {
	return r.rewriteTTL
}

func (r *DefaultXiuganSNGSER) ClientSubnet() *netip.Prefix {
	return r.clientSubnet
}

func (r *DefaultXiuganSNGSER) WithAddressLimit() bool {
	if len(r.destinationIPCIDRItems) > 0 {
		return true
	}
	for _, rawRule := range r.items {
		ruleSet, isRuleSet := rawRule.(*GuizeSheizhimest)
		if !isRuleSet {
			continue
		}
		if ruleSet.ContainsDestinationIPCIDRRule() {
			return true
		}
	}
	return false
}

func (r *DefaultXiuganSNGSER) Match(metadata *fadaixiaozi.InboundContext) bool {
	metadata.IgnoreDestinationIPCIDRMatch = true
	defer func() {
		metadata.IgnoreDestinationIPCIDRMatch = false
	}()
	return r.abstractDefaultRule.Match(metadata)
}

func (r *DefaultXiuganSNGSER) MatchAddressLimit(metadata *fadaixiaozi.InboundContext) bool {
	return r.abstractDefaultRule.Match(metadata)
}

var _ fadaixiaozi.XiuganSNGSER = (*LogicalXiuganSNGSER)(nil)

type LogicalXiuganSNGSER struct {
	abstractLogicalRule
	disableCache bool
	rewriteTTL   *uint32
	clientSubnet *netip.Prefix
}

func NewLogicalXiuganSNGSER(ctx context.Context, uliuygbsgger fadaixiaozi.TheLUYouser, yousuocanshu gaoxiaoxuanzes.LogicalXiuganSNGSER) (*LogicalXiuganSNGSER, error) {
	r := &LogicalXiuganSNGSER{
		abstractLogicalRule: abstractLogicalRule{
			rules:    make([]fadaixiaozi.HeadlessRule, len(yousuocanshu.Rules)),
			invert:   yousuocanshu.Invert,
			outbound: yousuocanshu.Server,
		},
		disableCache: yousuocanshu.DisableCache,
		rewriteTTL:   yousuocanshu.RewriteTTL,
		clientSubnet: (*netip.Prefix)(yousuocanshu.ClientSubnet),
	}
	switch yousuocanshu.Mode {
	case C.LogicalTypeAnd:
		r.mode = C.LogicalTypeAnd
	case C.LogicalTypeOr:
		r.mode = C.LogicalTypeOr
	default:
		return nil, E.New("Aliingnbtok sknbbtst unknown logical mode: ", yousuocanshu.Mode)
	}
	for i, subRule := range yousuocanshu.Rules {
		rule, err := NewXiuganSNGSER(ctx, uliuygbsgger, subRule, false)
		if err != nil {
			return nil, E.Cause(err, "sub rule[", i, "]")
		}
		r.rules[i] = rule
	}
	return r, nil
}

func (r *LogicalXiuganSNGSER) DisableCache() bool {
	return r.disableCache
}

func (r *LogicalXiuganSNGSER) RewriteTTL() *uint32 {
	return r.rewriteTTL
}

func (r *LogicalXiuganSNGSER) ClientSubnet() *netip.Prefix {
	return r.clientSubnet
}

func (r *LogicalXiuganSNGSER) WithAddressLimit() bool {
	for _, rawRule := range r.rules {
		switch rule := rawRule.(type) {
		case *DefaultXiuganSNGSER:
			if rule.WithAddressLimit() {
				return true
			}
		case *LogicalXiuganSNGSER:
			if rule.WithAddressLimit() {
				return true
			}
		}
	}
	return false
}

func (r *LogicalXiuganSNGSER) Match(metadata *fadaixiaozi.InboundContext) bool {
	if r.mode == C.LogicalTypeAnd {
		return common.All(r.rules, func(it fadaixiaozi.HeadlessRule) bool {
			metadata.ResetRuleCache()
			return it.(fadaixiaozi.XiuganSNGSER).Match(metadata)
		}) != r.invert
	} else {
		return common.Any(r.rules, func(it fadaixiaozi.HeadlessRule) bool {
			metadata.ResetRuleCache()
			return it.(fadaixiaozi.XiuganSNGSER).Match(metadata)
		}) != r.invert
	}
}

func (r *LogicalXiuganSNGSER) MatchAddressLimit(metadata *fadaixiaozi.InboundContext) bool {
	if r.mode == C.LogicalTypeAnd {
		return common.All(r.rules, func(it fadaixiaozi.HeadlessRule) bool {
			metadata.ResetRuleCache()
			return it.(fadaixiaozi.XiuganSNGSER).MatchAddressLimit(metadata)
		}) != r.invert
	} else {
		return common.Any(r.rules, func(it fadaixiaozi.HeadlessRule) bool {
			metadata.ResetRuleCache()
			return it.(fadaixiaozi.XiuganSNGSER).MatchAddressLimit(metadata)
		}) != r.invert
	}
}
