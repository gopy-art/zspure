package ssh

import (
	"zspure/modules/model"
	dropbear "zspure/modules/ssh/Dropbear"
	openssh "zspure/modules/ssh/OpenSSH"
	rosssh "zspure/modules/ssh/Rosssh"
)

func NewSSH() []model.ModuleMethods {
	return []model.ModuleMethods{
		&openssh.OpenSSH{},
		&dropbear.Dropbear{},
		&rosssh.ROSSSH{},
	}
}

func NewSSHScanner() *SSHScanning {
	return new(SSHScanning)
}
