package ssh

import (
	"strings"
	"zspure/modules/model"
	cisco "zspure/modules/ssh/Cisco"
	dopra "zspure/modules/ssh/Dopra"
	dropbear "zspure/modules/ssh/Dropbear"
	flowssh "zspure/modules/ssh/FlowSsh"
	huawei "zspure/modules/ssh/Huawei"
	lancom "zspure/modules/ssh/Lancom"
	libssh "zspure/modules/ssh/Libssh"
	modsftp "zspure/modules/ssh/Mod_sftp"
	mpssh "zspure/modules/ssh/MpSSH"
	openssh "zspure/modules/ssh/OpenSSH"
	paramiko "zspure/modules/ssh/Paramiko"
	romsshell "zspure/modules/ssh/RomSShell"
	rosssh "zspure/modules/ssh/Rosssh"
	zyxel "zspure/modules/ssh/Zyxel"
)

func NewSSH() []model.ModuleMethods {
	return []model.ModuleMethods{
		&openssh.OpenSSH{},
		&cisco.Cisco{},
		&dopra.Dopra{},
		&dropbear.Dropbear{},
		&flowssh.FlowSSH{},
		&huawei.Huawei{},
		&lancom.Lancom{},
		&modsftp.Modsftp{},
		&mpssh.MPSSH{},
		&romsshell.RomSShell{},
		&rosssh.ROSSSH{},
		&zyxel.Zyxel{},
		&paramiko.Paramiko{},
		&libssh.LibSSH{},
	}
}

func NewSSHScanner() *SSHScanning {
	return new(SSHScanning)
}

func isSSHBanner(banner string) bool {
    banner = strings.TrimSpace(banner)
    return strings.HasPrefix(banner, "SSH-") ||
           strings.Contains(banner, "SSH-")
}