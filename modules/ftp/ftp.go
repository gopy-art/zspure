package ftp

import (
	tenor "zspure/modules/ftp/Tenor"
	titan "zspure/modules/ftp/Titan"
	tnftpd "zspure/modules/ftp/Tnftpd"
	trimble "zspure/modules/ftp/Trimble"
	typsoft "zspure/modules/ftp/Typsoft"
	uclinux "zspure/modules/ftp/UClinux"
	vodaphone "zspure/modules/ftp/Vodaphone"
	vsftpd "zspure/modules/ftp/VsFtpd"
	vxworks "zspure/modules/ftp/VxWorks"
	warftpd "zspure/modules/ftp/WarFTPd"
	westerndigital "zspure/modules/ftp/WesternDigital"
	wftpd "zspure/modules/ftp/Wftpd"
	windriver "zspure/modules/ftp/WindRiver"
	wsftp "zspure/modules/ftp/Wsftp"
	xerox "zspure/modules/ftp/Xerox"
	xlight "zspure/modules/ftp/Xlight"
	zte "zspure/modules/ftp/ZTE"
	zxfs "zspure/modules/ftp/Zxfs"
	zyxel "zspure/modules/ftp/ZyXel"
	"zspure/modules/model"
)

func NewFTP() []model.ModuleMethods {
	return []model.ModuleMethods{
		&tenor.TenorMultipath{},
		&titan.TitanWindowsSystems{},
		&tnftpd.TnftpdTcpService{},
		&trimble.Trimble{},
		&typsoft.TypsoftWindowsSystems{},
		&uclinux.UClinuxServer{},
		&vsftpd.VsFTPdLinuxSystems{},
		&vxworks.VxWorksSystems{},
		&warftpd.WarFTPdWindowsSystems{},
		&westerndigital.WesternDigital{},
		&wftpd.WFTPdWindowsSystems{},
		&windriver.WindRiver{},
		&wsftp.WS_FTPServer{},
		&xerox.Xerox{},
		&xlight.XlightWindowsSystems{},
		&zte.ZTERouterFTP{},
		&zxfs.ZXFSFileSystem{},
		&zyxel.ZyXelRouterFTP{},
		&vodaphone.Vodaphone{},
	}
}