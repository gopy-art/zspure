package modbus

import (
	abb "zspure/modules/modbus/Abb"
	actl "zspure/modules/modbus/Actl"
	avatechmei "zspure/modules/modbus/Avatech_Mei"
	computec "zspure/modules/modbus/Computec"
	crouzet "zspure/modules/modbus/Crouzet"
	flexim "zspure/modules/modbus/Flexim"
	kontakttechnik "zspure/modules/modbus/Kontakttechnik"
	label "zspure/modules/modbus/LAB-EL"
	lantronix "zspure/modules/modbus/Lantronix"
	ocmprocf "zspure/modules/modbus/OcmProCF"
	panasonic "zspure/modules/modbus/Panasonic"
	rockwell "zspure/modules/modbus/Rockwell"
	seelectronic "zspure/modules/modbus/SEElectronic"
	schniderelectric "zspure/modules/modbus/Schnider_Electric"
	siemens "zspure/modules/modbus/Siemens"
	solar "zspure/modules/modbus/Solar"
	telemecanique "zspure/modules/modbus/Telemecanique"
	"zspure/modules/model"
)

func NewMODBUS() []model.ModuleMethods {
	return []model.ModuleMethods{
		&abb.Abb{},
		&actl.Actl{},
		&avatechmei.AvatechMei{},
		&computec.Computec{},
		&crouzet.Crouzet{},
		&flexim.Flexim{},
		&kontakttechnik.WAGOKontakttechnikGmbH{},
		&label.Lab_EL{},
		&lantronix.Lantronix{},
		&ocmprocf.OcmProCF{},
		&panasonic.Panasonic{},
		&rockwell.Rockwell{},
		&schniderelectric.SchniderElectric{},
		&seelectronic.SeElectronic{},
		&siemens.Siemens{},
		&solar.Solar{},
		&telemecanique.Telemecanique{},
	}
}

func NewMODBUSScanner() *ModbusScanning {
	return new(ModbusScanning)
}
