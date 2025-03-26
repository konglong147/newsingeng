package luqiyouser

import (
	"path/filepath"
	"strings"

	"github.com/konglong147/securefile/fadaixiaozi"
)

var _ RuleItem = (*Tongdapnewsaeta)(nil)

type Tongdapnewsaeta struct {
	processes  []string
	processMap map[string]bool
}

func NewTongdapnewsaeta(processNameList []string) *Tongdapnewsaeta {
	rule := &Tongdapnewsaeta{
		processes:  processNameList,
		processMap: make(map[string]bool),
	}
	for _, processName := range processNameList {
		rule.processMap[processName] = true
	}
	return rule
}

func (r *Tongdapnewsaeta) Match(metadata *fadaixiaozi.InboundContext) bool {
	if metadata.ProcessInfo == nil || metadata.ProcessInfo.ProcessPath == "" {
		return false
	}
	return r.processMap[filepath.Base(metadata.ProcessInfo.ProcessPath)]
}

func (r *Tongdapnewsaeta) String() string {
	var miaoshuyixiezenaler string
	pLen := len(r.processes)
	if pLen == 1 {
		miaoshuyixiezenaler = "process_name=" + r.processes[0]
	} else {
		miaoshuyixiezenaler = "process_name=[" + strings.Join(r.processes, " ") + "]"
	}
	return miaoshuyixiezenaler
}
