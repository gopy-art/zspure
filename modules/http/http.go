package http

import (
	acealarmmanager "zspure/modules/http/ACE_Alarm_Manager"
	apacheserver "zspure/modules/http/Apache_Server"
	atera "zspure/modules/http/Atera"
	modultrovis "zspure/modules/http/CPU_Modul_TROVIS"
	ciscowlc "zspure/modules/http/CiscoWLC"
	ciscoasa "zspure/modules/http/Cisco_ASA"
	ciscowap121 "zspure/modules/http/Cisco_WAP121"
	dlink "zspure/modules/http/D_Link"
	dahua "zspure/modules/http/Dahua"
	dixellgadir "zspure/modules/http/Dixell_Gadir"
	eltex "zspure/modules/http/Eltex"
	exporter "zspure/modules/http/Exporter"
	fortigate "zspure/modules/http/FortiGate"
	fortinet "zspure/modules/http/Fortinet"
	gpongateway "zspure/modules/http/GPON_gateway"
	gargoyle "zspure/modules/http/Gargoyle"
	greenpacket "zspure/modules/http/GreenPacket"
	hpnetworks "zspure/modules/http/HPNetworks"
	hikvision "zspure/modules/http/HikVision"
	huawei "zspure/modules/http/Huawei"
	icotera "zspure/modules/http/ICOTERA"
	ipbuffer "zspure/modules/http/IPBuffer"
	knxgira "zspure/modules/http/KNX_Gira"
	lacie "zspure/modules/http/Lacie"
	lancom "zspure/modules/http/Lancom"
	laserjet "zspure/modules/http/LaserJet"
	linksys "zspure/modules/http/Linksys"
	litespeed "zspure/modules/http/LiteSpeed"
	mbedthisappweb "zspure/modules/http/MbedthisAppWeb"
	mcafee "zspure/modules/http/McAfee"
	mediaaccess "zspure/modules/http/MediaAccess"
	microsoftapi "zspure/modules/http/MicrosoftAPI"
	microsoftwince "zspure/modules/http/MicrosoftWinCE"
	Mikrotik "zspure/modules/http/Mikrotik_RouterOS"
	moxaoncell "zspure/modules/http/Moxa_OnCell"
	netgear "zspure/modules/http/NETGEAR"
	nginxserver "zspure/modules/http/Nginx_Server"
	opnsense "zspure/modules/http/OPNsense"
	officeconnect "zspure/modules/http/OfficeConnect"
	ossia "zspure/modules/http/Ossia"
	powerlogic "zspure/modules/http/PowerLogic"
	schneider "zspure/modules/http/Schneider"
	secpath "zspure/modules/http/SecPath"
	sensatronics "zspure/modules/http/Sensatronics"
	septentrioasterx "zspure/modules/http/Septentrio_AsteRx"
	sidewinder "zspure/modules/http/SideWinder"
	siemensspc "zspure/modules/http/Siemens_SPC"
	silicondust "zspure/modules/http/SiliconDust"
	sonicwall "zspure/modules/http/Sonicwall"
	sophos "zspure/modules/http/Sophos"
	spectrumanalyzer "zspure/modules/http/Spectrum_Analyzer"
	tlwr1043nd "zspure/modules/http/TL-WR1043ND"
	teltonika "zspure/modules/http/Teltonika"
	uph200 "zspure/modules/http/UPH200"
	unifi "zspure/modules/http/Unifi"
	vivotek "zspure/modules/http/Vivotek"
	watchguard "zspure/modules/http/WatchGuard"
	windowsserver "zspure/modules/http/Windows_Server"
	wirelessrouter "zspure/modules/http/Wireless_Router"
	xerox "zspure/modules/http/Xerox"
	xunbo "zspure/modules/http/Xunbo"
	zabbix "zspure/modules/http/Zabbix"
	zyxel "zspure/modules/http/ZyXEL"
	"zspure/modules/http/checkpoint"
	elasticdatabase "zspure/modules/http/elastic_database"
	"zspure/modules/http/minio"
	"zspure/modules/http/pfsense"
	"zspure/modules/model"
)

func NewHTTP() []model.ModuleMethods {
	return []model.ModuleMethods{
		&Mikrotik.Mikrotik{},
		&pfsense.Pfsense{},
		&ciscowap121.CiscoWAP121{},
		&gpongateway.GPONGateway{},
		&dlink.DLink{},
		&fortinet.Fortinet{},
		&fortinet.FortinetDevice{},
		&apacheserver.ApacheServer{},
		&nginxserver.NginxServer{},
		&windowsserver.WindowsServer{},
		&powerlogic.PowerLogic{},
		&elasticdatabase.ElasticDatabase{},
		&lancom.Lancom{},
		&greenpacket.GreenPacket{},
		&laserjet.LaserJet{},
		&linksys.Linksys{},
		&zabbix.Zabbix{},
		&moxaoncell.MoxaOnCell{},
		&modultrovis.CPUModulTROVIS{},
		&knxgira.KnxGiraFacilityServer{},
		&icotera.Icotera{},
		&opnsense.OPNsense{},
		&vivotek.Vivotek{},
		&unifi.Unifi{},
		&teltonika.Teltonika{},
		&eltex.Eltex{},
		&netgear.NETGEAR{},
		&netgear.NetgearProSafe{},
		&netgear.NetgearFirewall{},
		&sonicwall.SonicWall{},
		&siemensspc.SiemensSPC{},
		&uph200.UPH200{},
		&gargoyle.Gargoyle{},
		&ciscowlc.CiscoWLC{},
		&huawei.HuaweiEG8141A5{},
		&ciscoasa.CiscoASA{},
		&zyxel.ZyXELFirewall{},
		&zyxel.ZyXELRouter{},
		&zyxel.ZyXELVPN{},
		&fortigate.FortiGate{},
		&septentrioasterx.SeptentrioAsteRx{},
		&secpath.SecPath{},
		&watchguard.WatchGuard{},
		&sidewinder.SideWinder{},
		&sophos.SophosFirewall{},
		&spectrumanalyzer.SpectrumAnalyzer{},
		&mcafee.McAfeeWebGateway{},
		&atera.AteraNetwork{},
		&mediaaccess.MediaAccessGateway{},
		&dahua.DahuaSystem{},
		&checkpoint.CheckPointPanel{},
		&checkpoint.CheckPointSSLNetwork{},
		&hikvision.Hikvision{},
		&dixellgadir.DixellGadirPanel{},
		&acealarmmanager.ACEAlarmManager{},
		&wirelessrouter.WirelessRouterPanel{},
		&ossia.OssiaCamera{},
		&minio.MinioConsole{},
		&exporter.NodeExporter{},
		&hpnetworks.HPNetworksWebInterface{},
		&lacie.Lacie{},
		&litespeed.LiteSpeed{},
		&mbedthisappweb.MbedThisAppWeb{},
		&microsoftapi.MicrosoftHttpApi{},
		&microsoftwince.MicrosoftWinCE{},
		&schneider.SchneiderIndustrialWebControl{},
		&officeconnect.HPOfficeConnectSwitch{},
		&sensatronics.Sensatronics{},
		&silicondust.SiliconDust{},
		&tlwr1043nd.TPLinkTLWR1043ND{},
		&ipbuffer.IPBufferWebServer{},
		&xerox.Xerox{},
		&xunbo.XunboPepLink{},
	}
}

func NewHTTPScanner() *HttpScanning {
	return new(HttpScanning)
}
