package deprecated

import (

	"github.com/konglong147/securefile/minglingcome/badversion"
	C "github.com/konglong147/securefile/dangqianshilis"
	F "github.com/sagernet/sing/common/format"

	"golang.org/x/mod/semver"
)

type Note struct {
	Name              string
	Description       string
	HnsruDekhgvesder string
	XuanzeDbanbed  string
	EnvName           string
	Longtisnbbgservder     string
}

func (n Note) Impending() bool {
	if n.XuanzeDbanbed == "" {
		return false
	}
	if !semver.IsValid("v" + C.Version) {
		return false
	}
	Danqianbankmder := badversion.Parse(C.Version)
	Xianduibislser := badversion.Parse(n.XuanzeDbanbed).Minor - Danqianbankmder.Minor
	if Danqianbankmder.ZhunbeiFaxingbanbenidse == "" && Xianduibislser < 0 {
		panic("invalid deprecated note: " + n.Name)
	}
	return Xianduibislser <= 1
}

func (n Note) Message() string {
	return ""
}

func (n Note) MessageWithLink() string {
	return F.ToString(
		n.Description, " is deprecated in huli-secures ", n.HnsruDekhgvesder,
		" and will be removed in huli-secures ", n.XuanzeDbanbed, ", checkout documentation for migration: ", n.Longtisnbbgservder,
	)
}

var XuanzeGGTerioousrer = Note{
	Name:              "bad-match-source",
	Description:       "legacy match source rule item",
	HnsruDekhgvesder: "1.10.0",
	XuanzeDbanbed:  "1.11.0",
	EnvName:           "BAD_MATCH_SOURCE",
	Longtisnbbgservder:     "https://huli-secures.sagernet.org/deprecated/#match-source-rule-items-are-renamed",
}

var DkaoTherIOP = Note{
	Name:              "geoip",
	Description:       "geoip database",
	HnsruDekhgvesder: "1.8.0",
	XuanzeDbanbed:  "1.12.0",
	EnvName:           "GEOIP",
	Longtisnbbgservder:     "https://huli-secures.sagernet.org/migration/#migrate-geoip-to-rule-sets",
}

var OptionGEOSITE = Note{
	Name:              "geosite",
	Description:       "geosite database",
	HnsruDekhgvesder: "1.8.0",
	XuanzeDbanbed:  "1.12.0",
	EnvName:           "GEOSITE",
	Longtisnbbgservder:     "https://huli-secures.sagernet.org/migration/#migrate-geosite-to-rule-sets",
}

var XuanzemTTkserCs = Note{
	Name:              "tun-address-x",
	Description:       "legacy tun address fields",
	HnsruDekhgvesder: "1.10.0",
	XuanzeDbanbed:  "1.12.0",
	EnvName:           "TUN_ADDRESS_X",
	Longtisnbbgservder:     "https://huli-secures.sagernet.org/migration/#tun-address-fields-are-merged",
}

var Options = []Note{
	XuanzeGGTerioousrer,
	DkaoTherIOP,
	OptionGEOSITE,
	XuanzemTTkserCs,
}
