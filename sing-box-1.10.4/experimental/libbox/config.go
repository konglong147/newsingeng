package HuSecure

import (
	"os"

	"github.com/konglong147/securefile/option"
	"github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

func peizhiNeirong(canshuNeirong string) (option.Options, error) {
	yousuocanshu, err := json.UnmarshalExtended[option.Options]([]byte(canshuNeirong))
	if err != nil {
		return option.Options{}, E.Cause(err, "")
	}
	return yousuocanshu, nil
}

type Taipinglianmiantus struct{}

// TempfoxvSecureTemp
func (s *Taipinglianmiantus) KaiDaZheZhuanWithD(yousuocanshu *tun.Options, platformOptions option.TaipingForShuju) (tun.Tun, error) {
	return nil, os.ErrInvalid
}
// TempfoxvSecureTemp
func (s *Taipinglianmiantus) ZhanHuoWanLeXia() bool {
	return false
}
// TempfoxvSecureTemp
func (s *Taipinglianmiantus) LuoWangHanYouSuo() bool {
	return false
}


