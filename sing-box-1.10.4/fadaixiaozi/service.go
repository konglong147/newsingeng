package fadaixiaozi

type Service interface {
	Start() error
	Close() error
}
