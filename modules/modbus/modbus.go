package modbus

import (
	kontakttechnik "zspure/modules/modbus/Kontakttechnik"
	label "zspure/modules/modbus/LAB-EL"
	lantronix "zspure/modules/modbus/Lantronix"
	ocmprocf "zspure/modules/modbus/OcmProCF"
	panasonic "zspure/modules/modbus/Panasonic"
	rockwell "zspure/modules/modbus/Rockwell"
	seelectronic "zspure/modules/modbus/SEElectronic"
	schniderelectric "zspure/modules/modbus/Schnider_Electric"
	siemens "zspure/modules/modbus/Siemens"
	telemecanique "zspure/modules/modbus/Telemecanique"
	"zspure/modules/model"
)

func NewMODBUS() []model.ModuleMethods {
	return []model.ModuleMethods{
		&kontakttechnik.WAGOKontakttechnikGmbH{},
		&label.Lab_EL{},
		&lantronix.Lantronix{},
		&ocmprocf.OcmProCF{},
		&panasonic.Panasonic{},
		&rockwell.Rockwell{},
		&schniderelectric.SchniderElectric{},
		&seelectronic.SeElectronic{},
		&siemens.Siemens{},
		&telemecanique.Telemecanique{},
	}
}