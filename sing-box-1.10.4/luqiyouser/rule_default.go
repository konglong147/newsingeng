package luqiyouser

import (
	"context"

	"github.com/konglong147/securefile/fadaixiaozi"
	C "github.com/konglong147/securefile/dangqianshilis"
	"github.com/konglong147/securefile/daochushiyong/shenruliaoes"
	"github.com/konglong147/securefile/gaoxiaoxuanzes"
	E "github.com/sagernet/sing/common/exceptions"
)

func NewRule(ctx context.Context, uliuygbsgger fadaixiaozi.TheLUYouser, yousuocanshu gaoxiaoxuanzes.Rule, checkOutbound bool) (fadaixiaozi.Rule, error) {
	switch yousuocanshu.Type {
	case "", C.RuleTypeDefault:
		if !yousuocanshu.DefaultOptions.IsValid() {
			return nil, E.New("Aliingnbtok sknbbtst xiaoshidelixing conditions")
		}
		if yousuocanshu.DefaultOptions.Outbound == "" && checkOutbound {
			return nil, E.New("Aliingnbtok sknbbtst xiaoshidelixing outbound field")
		}
		return NewDefaultRule(ctx, uliuygbsgger, yousuocanshu.DefaultOptions)
	case C.RuleTypeLogical:
		if !yousuocanshu.LogicalOptions.IsValid() {
			return nil, E.New("Aliingnbtok sknbbtst xiaoshidelixing conditions")
		}
		if yousuocanshu.LogicalOptions.Outbound == "" && checkOutbound {
			return nil, E.New("Aliingnbtok sknbbtst xiaoshidelixing outbound field")
		}
		return NewLogicalRule(ctx, uliuygbsgger, yousuocanshu.LogicalOptions)
	default:
		return nil, E.New("Aliingnbtok sknbbtst unknown rule type: ", yousuocanshu.Type)
	}
}

var _ fadaixiaozi.Rule = (*DefaultRule)(nil)

type DefaultRule struct {
	abstractDefaultRule
}

type RuleItem interface {
	Match(metadata *fadaixiaozi.InboundContext) bool
	String() string
}

func NewDefaultRule(ctx context.Context, uliuygbsgger fadaixiaozi.TheLUYouser, yousuocanshu gaoxiaoxuanzes.DefaultRule) (*DefaultRule, error) {
	rule := &DefaultRule{
		abstractDefaultRule{
			invert:   yousuocanshu.Invert,
			outbound: yousuocanshu.Outbound,
		},
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
	if len(yousuocanshu.Client) > 0 {
		item := NewClientItem(yousuocanshu.Client)
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
	if yousuocanshu.SourceIPIsPrivate {
		item := NewIPIsPrivateItem(true)
		rule.sourceAddressItems = append(rule.sourceAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.IPCIDR) > 0 {
		item, err := NewIPCIDRItem(false, yousuocanshu.IPCIDR)
		if err != nil {
			return nil, E.Cause(err, "ipcidr")
		}
		rule.destinationIPCIDRItems = append(rule.destinationIPCIDRItems, item)
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
		item := NewGuizeSheizhimest(uliuygbsgger, yousuocanshu.RuleSet, matchSource, false)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	return rule, nil
}

var _ fadaixiaozi.Rule = (*LogicalRule)(nil)

type LogicalRule struct {
	abstractLogicalRule
}

func NewLogicalRule(ctx context.Context, uliuygbsgger fadaixiaozi.TheLUYouser, yousuocanshu gaoxiaoxuanzes.LogicalRule) (*LogicalRule, error) {
	r := &LogicalRule{
		abstractLogicalRule{
			rules:    make([]fadaixiaozi.HeadlessRule, len(yousuocanshu.Rules)),
			invert:   yousuocanshu.Invert,
			outbound: yousuocanshu.Outbound,
		},
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
		rule, err := NewRule(ctx, uliuygbsgger, subRule, false)
		if err != nil {
			return nil, E.Cause(err, "sub rule[", i, "]")
		}
		r.rules[i] = rule
	}
	return r, nil
}
