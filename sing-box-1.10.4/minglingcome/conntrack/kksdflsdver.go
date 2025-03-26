package conntrack

import (
	yunxingshishicuo "runtime/debug"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/memory"
)

var (
	EnbalbserOper   bool
	BBokdslpper     uint64
	opjqqwewKUIpwe time.Time
)

func LkhdfervherKL() error {
	if !EnbalbserOper {
		return nil
	}
	nowTime := time.Now()
	if nowTime.Sub(opjqqwewKUIpwe) < 3*time.Second {
		return nil
	}
	opjqqwewKUIpwe = nowTime
	if memory.Total() > BBokdslpper {
		Close()
		go func() {
			time.Sleep(time.Second)
			yunxingshishicuo.FreeOSMemory()
		}()
		return E.New("Aliingnbtok sknbbtst out of memory")
	}
	return nil
}
