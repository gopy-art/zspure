package ssh

import (
	"zspure/modules/model"
	cisco "zspure/modules/ssh/Cisco"
	dopra "zspure/modules/ssh/Dopra"
	dropbear "zspure/modules/ssh/Dropbear"
	huawei "zspure/modules/ssh/Huawei"
	lancom "zspure/modules/ssh/Lancom"
	openssh "zspure/modules/ssh/OpenSSH"
	rosssh "zspure/modules/ssh/Rosssh"
	zyxel "zspure/modules/ssh/Zyxel"
)

func NewSSH() []model.ModuleMethods {
	return []model.ModuleMethods{
		&openssh.OpenSSH{},
		&cisco.Cisco{},
		&dopra.Dopra{},
		&dropbear.Dropbear{},
		&huawei.Huawei{},
		&lancom.Lancom{},
		&rosssh.ROSSSH{},
		&zyxel.Zyxel{},
	}
}

func NewSSHScanner() *SSHScanning {
	return new(SSHScanning)
}
