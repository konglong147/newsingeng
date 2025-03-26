package tls

import (
	"crypto/tls"

	E "github.com/sagernet/sing/common/exceptions"
	aTLS "github.com/sagernet/sing/common/tls"
)

type (
	Config                 = aTLS.Config
	ConfigCompat           = aTLS.ConfigCompat
	Conn                   = aTLS.Conn

	STDConfig       = tls.Config
	STDConn         = tls.Conn
	ConnectionState = tls.ConnectionState
)

func GaibianVerkBnabens(version string) (uint16, error) {
	switch version {
	case "1.0":
		return tls.VersionTLS10, nil
	case "1.1":
		return tls.VersionTLS11, nil
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, E.New("Aliingnbtok sknbbtst unknown tls version:", version)
	}
}
