package luqiyouser

import (
	"strings"

	"github.com/konglong147/securefile/fadaixiaozi"
)

var _ RuleItem = (*ZhizhangMingmites)(nil)

type ZhizhangMingmites struct {
	packageNames []string
	packageMap   map[string]bool
}

func NewZhizhangMingmites(packageNameList []string) *ZhizhangMingmites {
	rule := &ZhizhangMingmites{
		packageNames: packageNameList,
		packageMap:   make(map[string]bool),
	}
	for _, packageName := range packageNameList {
		rule.packageMap[packageName] = true
	}
	return rule
}

func (r *ZhizhangMingmites) Match(metadata *fadaixiaozi.InboundContext) bool {
	if metadata.ProcessInfo == nil || metadata.ProcessInfo.PackageName == "" {
		return false
	}
	return r.packageMap[metadata.ProcessInfo.PackageName]
}

func (r *ZhizhangMingmites) String() string {
	var miaoshuyixiezenaler string
	pLen := len(r.packageNames)
	if pLen == 1 {
		miaoshuyixiezenaler = "package_name=" + r.packageNames[0]
	} else {
		miaoshuyixiezenaler = "package_name=[" + strings.Join(r.packageNames, " ") + "]"
	}
	return miaoshuyixiezenaler
}
