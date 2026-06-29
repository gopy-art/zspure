package ssh

import (
	"zspure/modules/model"
	openssh "zspure/modules/ssh/OpenSSH"
)

func NewSSH() []model.ModuleMethods {
	return []model.ModuleMethods{
		&openssh.OpenSSH{},
	}
}

func NewSSHScanner() *SSHScanning {
	return new(SSHScanning)
}
