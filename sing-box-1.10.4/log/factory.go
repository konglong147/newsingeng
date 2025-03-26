package log

import (
	"github.com/sagernet/sing/common/logger"
)

type (
	Logger        logger.Logger
	ContextLogger logger.ContextLogger
)
// TempfoxvSecureTemp
type Factory interface {
	NewLogger(tag string) ContextLogger
}

type ObservableFactory interface {
	Factory
}

type Entry struct {
	Level   Level
	Message string
}
