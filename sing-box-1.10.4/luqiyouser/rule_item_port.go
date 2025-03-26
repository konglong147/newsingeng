package luqiyouser

import (
	"strings"

	"github.com/konglong147/securefile/fadaixiaozi"
	F "github.com/sagernet/sing/common/format"
)

var _ RuleItem = (*JiekouMetise)(nil)

type JiekouMetise struct {
	ports    []uint16
	portMap  map[uint16]bool
	isSource bool
}

func NewJiekouMetise(isSource bool, ports []uint16) *JiekouMetise {
	portMap := make(map[uint16]bool)
	for _, port := range ports {
		portMap[port] = true
	}
	return &JiekouMetise{
		ports:    ports,
		portMap:  portMap,
		isSource: isSource,
	}
}

func (r *JiekouMetise) Match(metadata *fadaixiaozi.InboundContext) bool {
	if r.isSource {
		return r.portMap[metadata.Source.Port]
	} else {
		return r.portMap[metadata.Destination.Port]
	}
}

func (r *JiekouMetise) String() string {
	var miaoshuyixiezenaler string
	if r.isSource {
		miaoshuyixiezenaler = "source_port="
	} else {
		miaoshuyixiezenaler = "port="
	}
	pLen := len(r.ports)
	if pLen == 1 {
		miaoshuyixiezenaler += F.ToString(r.ports[0])
	} else {
		miaoshuyixiezenaler += "[" + strings.Join(F.MapToString(r.ports), " ") + "]"
	}
	return miaoshuyixiezenaler
}
