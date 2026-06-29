package ssh

import (
	"zspure/modules/model"
	cisco "zspure/modules/ssh/Cisco"
	dropbear "zspure/modules/ssh/Dropbear"
	openssh "zspure/modules/ssh/OpenSSH"
	rosssh "zspure/modules/ssh/Rosssh"
)

func NewSSH() []model.ModuleMethods {
	return []model.ModuleMethods{
		&openssh.OpenSSH{},
		&cisco.Cisco{},
		&dropbear.Dropbear{},
		&rosssh.ROSSSH{},
	}
}

func NewSSHScanner() *SSHScanning {
	return new(SSHScanning)
}
