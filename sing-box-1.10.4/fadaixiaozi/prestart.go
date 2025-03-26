package fadaixiaozi

type PreStarter interface {
	PreStart() error
}

type PostStarter interface {
	PostStart() error
}
