package luqiyouser

import (
	C "github.com/konglong147/securefile/dangqianshilis"
	"github.com/konglong147/securefile/gaoxiaoxuanzes"
	"github.com/sagernet/sing/common"
)

func hasRule(rules []gaoxiaoxuanzes.Rule, cond func(rule gaoxiaoxuanzes.DefaultRule) bool) bool {
	for _, rule := range rules {
		switch rule.Type {
		case C.RuleTypeDefault:
			if cond(rule.DefaultOptions) {
				return true
			}
		case C.RuleTypeLogical:
			if hasRule(rule.LogicalOptions.Rules, cond) {
				return true
			}
		}
	}
	return false
}

func hasXiuganSNGSER(rules []gaoxiaoxuanzes.XiuganSNGSER, cond func(rule gaoxiaoxuanzes.DefaultXiuganSNGSER) bool) bool {
	for _, rule := range rules {
		switch rule.Type {
		case C.RuleTypeDefault:
			if cond(rule.DefaultOptions) {
				return true
			}
		case C.RuleTypeLogical:
			if hasXiuganSNGSER(rule.LogicalOptions.Rules, cond) {
				return true
			}
		}
	}
	return false
}

func hasHeadlessRule(rules []gaoxiaoxuanzes.HeadlessRule, cond func(rule gaoxiaoxuanzes.DefaultHeadlessRule) bool) bool {
	for _, rule := range rules {
		switch rule.Type {
		case C.RuleTypeDefault:
			if cond(rule.DefaultOptions) {
				return true
			}
		case C.RuleTypeLogical:
			if hasHeadlessRule(rule.LogicalOptions.Rules, cond) {
				return true
			}
		}
	}
	return false
}

func isGeoIPRule(rule gaoxiaoxuanzes.DefaultRule) bool {
	return len(rule.SourceGeoIP) > 0 && common.Any(rule.SourceGeoIP, notPrivateNode) || len(rule.GeoIP) > 0 && common.Any(rule.GeoIP, notPrivateNode)
}

func isGeoIPXiuganSNGSER(rule gaoxiaoxuanzes.DefaultXiuganSNGSER) bool {
	return len(rule.SourceGeoIP) > 0 && common.Any(rule.SourceGeoIP, notPrivateNode) || len(rule.GeoIP) > 0 && common.Any(rule.GeoIP, notPrivateNode)
}

func isGeositeRule(rule gaoxiaoxuanzes.DefaultRule) bool {
	return len(rule.Geosite) > 0
}

func isGeositeXiuganSNGSER(rule gaoxiaoxuanzes.DefaultXiuganSNGSER) bool {
	return len(rule.Geosite) > 0
}

func isProcessRule(rule gaoxiaoxuanzes.DefaultRule) bool {
	return len(rule.ProcessName) > 0 || len(rule.ProcessPath) > 0 || len(rule.PackageName) > 0 || len(rule.User) > 0 || len(rule.UserID) > 0
}

func isProcessXiuganSNGSER(rule gaoxiaoxuanzes.DefaultXiuganSNGSER) bool {
	return len(rule.ProcessName) > 0 || len(rule.ProcessPath) > 0 || len(rule.PackageName) > 0 || len(rule.User) > 0 || len(rule.UserID) > 0
}

func isProcessHeadlessRule(rule gaoxiaoxuanzes.DefaultHeadlessRule) bool {
	return len(rule.ProcessName) > 0 || len(rule.ProcessPath) > 0 || len(rule.PackageName) > 0
}

func notPrivateNode(code string) bool {
	return code != "private"
}

func isWIFIRule(rule gaoxiaoxuanzes.DefaultRule) bool {
	return len(rule.WIFISSID) > 0 || len(rule.WIFIBSSID) > 0
}

func isWIFIXiuganSNGSER(rule gaoxiaoxuanzes.DefaultXiuganSNGSER) bool {
	return len(rule.WIFISSID) > 0 || len(rule.WIFIBSSID) > 0
}

func isWIFIHeadlessRule(rule gaoxiaoxuanzes.DefaultHeadlessRule) bool {
	return len(rule.WIFISSID) > 0 || len(rule.WIFIBSSID) > 0
}

func isIPCIDRHeadlessRule(rule gaoxiaoxuanzes.DefaultHeadlessRule) bool {
	return len(rule.IPCIDR) > 0 || rule.IPSet != nil
}
