package ssh

import (
	"zspure/modules/model"
	dropbear "zspure/modules/ssh/Dropbear"
	openssh "zspure/modules/ssh/OpenSSH"
)

func NewSSH() []model.ModuleMethods {
	return []model.ModuleMethods{
		&openssh.OpenSSH{},
		&dropbear.Dropbear{},
	}
}

func NewSSHScanner() *SSHScanning {
	return new(SSHScanning)
}
