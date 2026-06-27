package pptp

import (
	"zspure/modules/model"
	pptpvpn "zspure/modules/pptp/pptp_vpn"
)

func NewPPTP() []model.ModuleMethods {
	return []model.ModuleMethods{
		&pptpvpn.PPTPVPN{},
	}
}

func NewPPTPScanner() *PPTPScanning {
	return new(PPTPScanning)
}
