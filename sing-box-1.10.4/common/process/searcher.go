package process

import (

	"github.com/konglong147/securefile/log"
	"github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"

)

type Searcher interface {
	
}

var ErrNotFound = E.New("process not found")

type Config struct {
	Logger         log.ContextLogger
	PackageManager tun.PackageManager
}

type Info struct {
	ProcessPath string
	PackageName string
	User        string
	UserId      int32
}
