package ssh

import (
	"zspure/modules/model"
	sshservice "zspure/modules/ssh/ssh_service"
)

func NewSSH() []model.ModuleMethods {
	return []model.ModuleMethods{
		&sshservice.SSHService{},
	}
}