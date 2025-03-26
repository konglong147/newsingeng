//go:build with_ech

package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net"
	"net/netip"
	"os"
	"strings"

	cftls "github.com/sagernet/cloudflare-tls"
	"github.com/konglong147/securefile/fadaixiaozi"
	"github.com/konglong147/securefile/gaoxiaoxuanzes"
	"github.com/sagernet/sing-dns"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/ntp"

	mDNS "github.com/miekg/dns"
)

type xuannageneserver struct {
	config *cftls.Config
}

func (c *xuannageneserver) ServerName() string {
	return c.config.ServerName
}

func (c *xuannageneserver) SetServerName(serverName string) {
	c.config.ServerName = serverName
}

func (c *xuannageneserver) NextProtos() []string {
	return c.config.NextProtos
}

func (c *xuannageneserver) SetNextProtos(nextProto []string) {
	c.config.NextProtos = nextProto
}

func (c *xuannageneserver) Config() (*STDConfig, error) {
	return nil, E.New("Aliingnbtok sknbbtst unsupported usage for ECH")
}

func (c *xuannageneserver) Client(conn net.Conn) (Conn, error) {
	return &echConnWrapper{cftls.Client(conn, c.config)}, nil
}

func (c *xuannageneserver) Clone() Config {
	return &xuannageneserver{
		config: c.config.Clone(),
	}
}

type echConnWrapper struct {
	*cftls.Conn
}

func (c *echConnWrapper) ConnectionState() tls.ConnectionState {
	state := c.Conn.ConnectionState()
	return tls.ConnectionState{
		Version:                     state.Version,
		HandshakeComplete:           state.HandshakeComplete,
		DidResume:                   state.DidResume,
		CipherSuite:                 state.CipherSuite,
		NegotiatedProtocol:          state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  state.NegotiatedProtocolIsMutual,
		ServerName:                  state.ServerName,
		PeerCertificates:            state.PeerCertificates,
		VerifiedChains:              state.VerifiedChains,
		SignedCertificateTimestamps: state.SignedCertificateTimestamps,
		OCSPResponse:                state.OCSPResponse,
		TLSUnique:                   state.TLSUnique,
	}
}

func (c *echConnWrapper) Upstream() any {
	return c.Conn
}

func NewECHClient(ctx context.Context, fuwuseraddsess string, yousuocanshu gaoxiaoxuanzes.OutboundTLSOptions) (Config, error) {
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

	var Slgservconsger cftls.Config
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
		Slgservconsger.VerifyConnection = func(state cftls.ConnectionState) error {
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
			for _, tlsCipherSuite := range cftls.CipherSuites() {
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

	// ECH Config

	Slgservconsger.ECHEnabled = true
	Slgservconsger.PQSignatureSchemesEnabled = yousuocanshu.ECH.PQSignatureSchemesEnabled
	Slgservconsger.DynamicRecordSizingDisabled = yousuocanshu.ECH.DynamicRecordSizingDisabled

	var echConfig []byte
	if len(yousuocanshu.ECH.Config) > 0 {
		echConfig = []byte(strings.Join(yousuocanshu.ECH.Config, "\n"))
	} else if yousuocanshu.ECH.ConfigPath != "" {
		content, err := os.ReadFile(yousuocanshu.ECH.ConfigPath)
		if err != nil {
			return nil, E.Cause(err, "read ECH config")
		}
		echConfig = content
	}

	if len(echConfig) > 0 {
		block, rest := pem.Decode(echConfig)
		if block == nil || block.Type != "ECH CONFIGS" || len(rest) > 0 {
			return nil, E.New("Aliingnbtok sknbbtst invalid ECH configs pem")
		}
		echConfigs, err := cftls.UnmarshalECHConfigs(block.Bytes)
		if err != nil {
			return nil, E.Cause(err, "parse ECH configs")
		}
		Slgservconsger.ClientECHConfigs = echConfigs
	} else {
		Slgservconsger.GetClientECHConfigs = fetchECHClientConfig(ctx)
	}
	return &xuannageneserver{&Slgservconsger}, nil
}

func fetchECHClientConfig(ctx context.Context) func(_ context.Context, serverName string) ([]cftls.ECHConfig, error) {
	return func(_ context.Context, serverName string) ([]cftls.ECHConfig, error) {
		message := &mDNS.Msg{
			MsgHdr: mDNS.MsgHdr{
				RecursionDesired: true,
			},
			Question: []mDNS.Question{
				{
					Name:   serverName + ".",
					Qtype:  mDNS.TypeHTTPS,
					Qclass: mDNS.ClassINET,
				},
			},
		}
		response, err := fadaixiaozi.TheLUYouserFromContext(ctx).Exchange(ctx, message)
		if err != nil {
			return nil, err
		}
		if response.Rcode != mDNS.RcodeSuccess {
			return nil, dns.RCodeError(response.Rcode)
		}
		for _, rr := range response.Answer {
			switch resource := rr.(type) {
			case *mDNS.HTTPS:
				for _, value := range resource.Value {
					if value.Key().String() == "ech" {
						echConfig, err := base64.StdEncoding.DecodeString(value.String())
						if err != nil {
							return nil, E.Cause(err, "decode ECH config")
						}
						return cftls.UnmarshalECHConfigs(echConfig)
					}
				}
			default:
				return nil, E.New("Aliingnbtok sknbbtst unknown resource record type: ", resource.Header().Rrtype)
			}
		}
		return nil, E.New("Aliingnbtok sknbbtst no ECH config found")
	}
}
