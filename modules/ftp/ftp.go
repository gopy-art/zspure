package ftp

import (
	alcatel "zspure/modules/ftp/Alcatel"
	allworx "zspure/modules/ftp/Allworx"
	apc "zspure/modules/ftp/Apc"
	asus "zspure/modules/ftp/Asus"
	axis "zspure/modules/ftp/Axis"
	belkin "zspure/modules/ftp/Belkin"
	bftpd "zspure/modules/ftp/Bftpd"
	bulletProof "zspure/modules/ftp/BulletProof"
	cerberus "zspure/modules/ftp/Cerberus"
	cesarFTP "zspure/modules/ftp/CesarFTP"
	dell "zspure/modules/ftp/Dell"
	dlink "zspure/modules/ftp/Dlink"
	drayTek "zspure/modules/ftp/DrayTek"
	dreambox "zspure/modules/ftp/Dreambox"
	ecosense "zspure/modules/ftp/Ecosense"
	fritzBox "zspure/modules/ftp/FRITZBox"
	filezilla "zspure/modules/ftp/Filezilla"
	fullrate "zspure/modules/ftp/Fullrate"
	gene6Ftpd "zspure/modules/ftp/Gene6Ftpd"
	genericCamera "zspure/modules/ftp/GenericCamera"
	genericDsl "zspure/modules/ftp/GenericDsl"
	genericUpdate "zspure/modules/ftp/GenericUpdate"
	hp "zspure/modules/ftp/Hp"
	ibm "zspure/modules/ftp/Ibm"
	iis "zspure/modules/ftp/Iis"
	ipTime "zspure/modules/ftp/IpTime"
	kebi "zspure/modules/ftp/Kebi"
	konicaMinolta "zspure/modules/ftp/KonicaMinolta"
	lacie "zspure/modules/ftp/Lacie"
	lantronix "zspure/modules/ftp/Lantronix"
	leightronix "zspure/modules/ftp/Leightronix"
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
	seagate "zspure/modules/ftp/Seagate"
	servuftpd "zspure/modules/ftp/ServuFtpd"
	sharp "zspure/modules/ftp/Sharp"
	softathome "zspure/modules/ftp/SoftAtHome"
	sony "zspure/modules/ftp/Sony"
	speedport "zspure/modules/ftp/SpeedPort"
	synology "zspure/modules/ftp/Synology"
	telindus "zspure/modules/ftp/Telindus"
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

var commands map[string]string = map[string]string{
	"SYST":         "SYST\r\n",         // System info
	"FEAT":         "FEAT\r\n",         // Features
	"STAT":         "STAT\r\n",         // Status
	"HELP":         "HELP\r\n",         // Help
	"PWD":          "PWD\r\n",          // Print working directory
	"TYPE A":       "TYPE A\r\n",       // ASCII mode
	"TYPE I":       "TYPE I\r\n",       // Binary mode
	"PASV":         "PASV\r\n",         // Passive mode
	"EPSV":         "EPSV\r\n",         // Extended passive mode
	"OPTS UTF8 ON": "OPTS UTF8 ON\r\n", // UTF-8 support
	"ALLO 1":       "ALLO 1\r\n",       // Allocate space
	"REST 0":       "REST 0\r\n",       // Restart position
	"SIZE /":       "SIZE /\r\n",       // File size
	"MDTM /":       "MDTM /\r\n",       // Modification time
}

func NewFTP() []model.ModuleMethods {
	return []model.ModuleMethods{
		&alcatel.Alcatel{},
		&allworx.Allworx{},
		&apc.Apc{},
		&asus.Asus{},
		&axis.Axis{},
		&belkin.Belkin{},
		&bftpd.Bftpd{},
		&bulletProof.BulletProof{},
		&cerberus.Cerberus{},
		&cesarFTP.CesarFTP{},
		&dell.Dell{},
		&dlink.Dlink{},
		&drayTek.DrayTek{},
		&dreambox.Dreambox{},
		&ecosense.Ecosense{},
		&filezilla.Filezilla{},
		&fritzBox.FRITZBox{},
		&fullrate.Fullrate{},
		&gene6Ftpd.Gene6Ftpd{},
		&genericCamera.GenericCamera{},
		&genericDsl.GenericDsl{},
		&genericUpdate.GenericUpdate{},
		&hp.Hp{},
		&ibm.Ibm{},
		&iis.Iis{},
		&ipTime.IpTime{},
		&kebi.Kebi{},
		&lacie.Lacie{},
		&lantronix.Lantronix{},
		&leightronix.Leightronix{},
		&konicaMinolta.KonicaMinolta{},
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
		&seagate.Seagate{},
		&servuftpd.ServuFtpd{},
		&sharp.Sharp{},
		&softathome.SoftAtHome{},
		&sony.SonyNetworkCamera{},
		&speedport.SpeedPort{},
		&synology.Synology{},
		&telindus.Telindus{},
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

func NewFTPScanner() *FtpScanning {
	return new(FtpScanning)
}