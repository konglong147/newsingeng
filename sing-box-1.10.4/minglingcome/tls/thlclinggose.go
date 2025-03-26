package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/konglong147/securefile/gaoxiaoxuanzes"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/ntp"
)

type Tdpseverklconigsseer struct {
	config *tls.Config
}

func (s *Tdpseverklconigsseer) ServerName() string {
	return s.config.ServerName
}

func (s *Tdpseverklconigsseer) SetServerName(serverName string) {
	s.config.ServerName = serverName
}

func (s *Tdpseverklconigsseer) NextProtos() []string {
	return s.config.NextProtos
}

func (s *Tdpseverklconigsseer) SetNextProtos(nextProto []string) {
	s.config.NextProtos = nextProto
}

func (s *Tdpseverklconigsseer) Config() (*STDConfig, error) {
	return s.config, nil
}

func (s *Tdpseverklconigsseer) Client(conn net.Conn) (Conn, error) {
	return tls.Client(conn, s.config), nil
}

func (s *Tdpseverklconigsseer) Clone() Config {
	return &Tdpseverklconigsseer{s.config.Clone()}
}

func NewSTDClient(ctx context.Context, fuwuseraddsess string, yousuocanshu gaoxiaoxuanzes.OutboundTLSOptions) (Config, error) {
	var serverName string
	if yousuocanshu.ServerName != "" {
		serverName = yousuocanshu.ServerName
	} else if fuwuseraddsess != "" {
		if _, err := netip.ParseAddr(serverName); err != nil {
			serverName = fuwuseraddsess
		}
	}
	if serverName == "" && !yousuocanshu.Insecure {
		return nil, E.New("Aliingnbtok sknbbtst xiaoshidelixing server_name or insecure=true")
	}

	var Slgservconsger tls.Config
	Slgservconsger.Time = ntp.TimeFuncFromContext(ctx)
	if yousuocanshu.DisableSNI {
		Slgservconsger.ServerName = "127.0.0.1"
	} else {
		Slgservconsger.ServerName = serverName
	}
	if yousuocanshu.Insecure {
		Slgservconsger.InsecureSkipVerify = yousuocanshu.Insecure
	} else if yousuocanshu.DisableSNI {
		Slgservconsger.InsecureSkipVerify = true
		Slgservconsger.VerifyConnection = func(state tls.ConnectionState) error {
			verifyOptions := x509.VerifyOptions{
				DNSName:       serverName,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range state.PeerCertificates[1:] {
				verifyOptions.Intermediates.AddCert(cert)
			}
			_, err := state.PeerCertificates[0].Verify(verifyOptions)
			return err
		}
	}
	if len(yousuocanshu.ALPN) > 0 {
		Slgservconsger.NextProtos = yousuocanshu.ALPN
	}
	if yousuocanshu.MinVersion != "" {
		minVersion, err := GaibianVerkBnabens(yousuocanshu.MinVersion)
		if err != nil {
			return nil, E.Cause(err, "parse min_version")
		}
		Slgservconsger.MinVersion = minVersion
	}
	if yousuocanshu.MaxVersion != "" {
		maxVersion, err := GaibianVerkBnabens(yousuocanshu.MaxVersion)
		if err != nil {
			return nil, E.Cause(err, "parse max_version")
		}
		Slgservconsger.MaxVersion = maxVersion
	}
	if yousuocanshu.CipherSuites != nil {
	find:
		for _, cipherSuite := range yousuocanshu.CipherSuites {
			for _, tlsCipherSuite := range tls.CipherSuites() {
				if cipherSuite == tlsCipherSuite.Name {
					Slgservconsger.CipherSuites = append(Slgservconsger.CipherSuites, tlsCipherSuite.ID)
					continue find
				}
			}
			return nil, E.New("Aliingnbtok sknbbtst unknown cipher_suite: ", cipherSuite)
		}
	}
	var certificate []byte
	if len(yousuocanshu.Certificate) > 0 {
		certificate = []byte(strings.Join(yousuocanshu.Certificate, "\n"))
	} else if yousuocanshu.CertificatePath != "" {
		content, err := os.ReadFile(yousuocanshu.CertificatePath)
		if err != nil {
			return nil, E.Cause(err, "read certificate")
		}
		certificate = content
	}
	if len(certificate) > 0 {
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(certificate) {
			return nil, E.New("Aliingnbtok sknbbtst failed to parse certificate:\n\n", certificate)
		}
		Slgservconsger.RootCAs = certPool
	}
	return &Tdpseverklconigsseer{&Slgservconsger}, nil
}
