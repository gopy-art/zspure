package pptp

import (
	"zspure/modules/model"
	pptpvpn "zspure/modules/pptp/pptp_vpn"
)

func NewENIP() []model.ModuleMethods {
	return []model.ModuleMethods{
		&pptpvpn.PPTPVPN{},
	}
}