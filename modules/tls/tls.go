package tls

import (
	"zspure/modules/model"
	ami "zspure/modules/tls/AMI"
	alcatel "zspure/modules/tls/Alcatel"
	aruba "zspure/modules/tls/Aruba"
	asusdevices "zspure/modules/tls/AsusDevices"
	asusrouter "zspure/modules/tls/AsusRouter"
	asusserver "zspure/modules/tls/AsusServer"
	cambiumnetworks "zspure/modules/tls/CambiumNetworks"
	checkpoint "zspure/modules/tls/CheckPoint"
	cyberoam "zspure/modules/tls/Cyberoam"
	dlink "zspure/modules/tls/DLink"
	deosag "zspure/modules/tls/DeosAg"
	draytek "zspure/modules/tls/DrayTek"
	endresshauser "zspure/modules/tls/EndressHauser"
	firepower "zspure/modules/tls/FirePower"
	fortinet "zspure/modules/tls/Fortinet"
	freenas "zspure/modules/tls/FreeNAS"
	grandstream "zspure/modules/tls/GrandStream"
	hpipg "zspure/modules/tls/HP-IPG"
	hillstone "zspure/modules/tls/Hillstone"
	hirschmann "zspure/modules/tls/Hirschmann"
	idrac "zspure/modules/tls/IDRAC"
	jetdirect "zspure/modules/tls/JetDirect"
	juniper "zspure/modules/tls/Juniper"
	konicaminolta "zspure/modules/tls/KonicaMinolta"
	lancom "zspure/modules/tls/Lancom"
	lexmark "zspure/modules/tls/Lexmark"
	lifesize "zspure/modules/tls/LifeSize"
	m0n0wall "zspure/modules/tls/M0n0wall"
	maipu "zspure/modules/tls/Maipu"
	microhard "zspure/modules/tls/Microhard"
	mitsubishi "zspure/modules/tls/Mitsubishi"
	motorola "zspure/modules/tls/Motorola"
	netgear "zspure/modules/tls/Netgear"
	opnsense "zspure/modules/tls/OPNsense"
	openwrt "zspure/modules/tls/Openwrt"
	opto22 "zspure/modules/tls/Opto22"
	osnexus "zspure/modules/tls/Osnexus"
	paloalto "zspure/modules/tls/PaloAlto"
	polycom "zspure/modules/tls/Polycom"
	qnap "zspure/modules/tls/QNAP"
	quantum "zspure/modules/tls/Quantum"
	raritan "zspure/modules/tls/Raritan"
	ruckuswireless "zspure/modules/tls/RuckusWireless"
	schneider "zspure/modules/tls/Schneider"
	seagate "zspure/modules/tls/Seagate"
	sharp "zspure/modules/tls/Sharp"
	siemens "zspure/modules/tls/Siemens"
	sierrawirelessairlink "zspure/modules/tls/SierraWirelessAirLink"
	sonicwall "zspure/modules/tls/SonicWall"
	sophos "zspure/modules/tls/Sophos"
	stormshield "zspure/modules/tls/Stormshield"
	sunmicrosystems "zspure/modules/tls/SunMicrosystems"
	supermicrocomputer "zspure/modules/tls/SuperMicroComputer"
	synology "zspure/modules/tls/Synology"
	tplink "zspure/modules/tls/TPLink"
	teltonika "zspure/modules/tls/Teltonika"
	tenda "zspure/modules/tls/Tenda"
	terramaster "zspure/modules/tls/TerraMaster"
	thecus "zspure/modules/tls/Thecus"
	topsec "zspure/modules/tls/Topsec"
	trane "zspure/modules/tls/Trane"
	tridiumniagara4 "zspure/modules/tls/TridiumNiagara4"
	trimble "zspure/modules/tls/Trimble"
	ubiquiti "zspure/modules/tls/Ubiquiti"
	uniview "zspure/modules/tls/Uniview"
	wago "zspure/modules/tls/Wago"
	watchguard "zspure/modules/tls/WatchGuard"
	westermo "zspure/modules/tls/Westermo"
	westerndigital "zspure/modules/tls/WesternDigital"
	xerox "zspure/modules/tls/Xerox"
	zte "zspure/modules/tls/ZTE"
	zyxel "zspure/modules/tls/ZyXEL"
	ixsystems "zspure/modules/tls/iXsystems"
	"zspure/modules/tls/pfsense"
)

func NewTLS() []model.ModuleMethods {
	return []model.ModuleMethods{
		&fortinet.Fortinet{},
		&opnsense.OPNsense{},
		&pfsense.Pfsense{},
		&sonicwall.SonicWall{},
		&sophos.Sophos{},
		&watchguard.WatchGuard{},
		&teltonika.Teltonika{},
		&lancom.Lancom{},
		&checkpoint.CheckPoint{},
		&firepower.CiscoFirePower{},
		&paloalto.PaloAlto{},
		&draytek.DrayTek{},
		&aruba.ArubaNetworks{},
		&zyxel.ZyXELGateway{},
		&tplink.TPLink{},
		&dlink.DLink{},
		&tenda.TendaRouter{},
		&alcatel.AlcatelNetworks{},
		&maipu.MaipuRouter{},
		&juniper.JuniperNetworks{},
		&siemens.SiemensSystems{},
		&openwrt.OpenwrtRouter{},
		&motorola.MotorolaSystems{},
		&cyberoam.Cyberoam{},
		&hillstone.HillstoneNetworks{},
		&stormshield.Stormshield{},
		&topsec.Topsec{},
		&zte.ZTEGateway{},
		&idrac.IDRACServer{},
		&synology.SynologyNAS{},
		&seagate.SeagateNAS{},
		&terramaster.TerraMaster{},
		&qnap.QNAPNAS{},
		&quantum.QuantumNetworks{},
		&freenas.FreeNAS{},
		&netgear.NetgearPanel{},
		&uniview.UniviewCamera{},
		&polycom.PolycomCamera{},
		&asusrouter.AsusRouter{},
		&asusdevices.AsusDevices{},
		&asusserver.AsusServer{},
		&grandstream.GrandStream{},
		&ubiquiti.Ubiquiti{},
		&cambiumnetworks.CambiumNetworks{},
		&sierrawirelessairlink.SierraWirelessAirLink{},
		&ruckuswireless.RuckusWireless{},
		&westermo.WestermoTeleindustrial{},
		&wago.WAGOIndustrialPanel{},
		&deosag.DEOSAG{},
		&trane.Trane{},
		&mitsubishi.Mitsubishi{},
		&endresshauser.EndressHauser{},
		&opto22.Opto22{},
		&tridiumniagara4.TridiumNiagara4{},
		&ami.AMI{},
		&trimble.Trimble{},
		&microhard.Microhard{},
		&schneider.SchneiderEcostruxure{},
		&hpipg.HPIRGHTTPS{},
		&ixsystems.IXsystem{},
		&jetdirect.JetDirect{},
		&konicaminolta.KonicaMinolta{},
		&lexmark.Lexmark{},
		&osnexus.OsnexusStorage{},
		&raritan.Raritan{},
		&sharp.Sharp{},
		&lifesize.LifeSizeTransitServer{},
		&sunmicrosystems.SunMicrosystems{},
		&supermicrocomputer.SuperMicroComputer{},
		&thecus.ThecusNAS{},
		&westerndigital.WesternDigital{},
		&xerox.Xerox{},
		&hirschmann.Hirschmann{},
		&m0n0wall.M0n0wallFreeBSD{},
	}
}