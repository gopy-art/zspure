package ftp

import (
	lexmark "zspure/modules/ftp/Lexmark"
	linksys "zspure/modules/ftp/Linksys"
	lutron "zspure/modules/ftp/Lutron"
	maygion "zspure/modules/ftp/Maygion"
	mikrotik "zspure/modules/ftp/MikroTik"
	nationalinstruments "zspure/modules/ftp/NationalInstruments"
	ncftpd "zspure/modules/ftp/NcFTPd"
	netapp "zspure/modules/ftp/NetApp"
	netgear "zspure/modules/ftp/Netgear"
	nucleus "zspure/modules/ftp/Nucleus"
	opto22 "zspure/modules/ftp/Opto22"
	overland "zspure/modules/ftp/Overland"
	proftpd "zspure/modules/ftp/ProFTPD"
	pureftpd "zspure/modules/ftp/PureFTPd"
	qnapturbo "zspure/modules/ftp/QnapTurbo"
	ricoh "zspure/modules/ftp/Ricoh"
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
		&lexmark.Lexmark{},
		&linksys.Linksys{},
		&lutron.Lutron{},
		&maygion.Maygion{},
		&mikrotik.Mikrotik{},
		&nationalinstruments.NationalInstruments{},
		&ncftpd.NcFTPd{},
		&netapp.NetApp{},
		&netgear.NetGearReadyNAS{},
		&nucleus.Nucleus{},
		&opto22.Opto22{},
		&overland.OverlandStorage{},
		&proftpd.ProFtpd{},
		&pureftpd.PureFTPD{},
		&qnapturbo.QnapTurboNas{},
		&ricoh.Ricoh{},
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