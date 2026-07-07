package upnp

import (
	devices "zspure/modules/upnp/Devices"
	"zspure/modules/model"
)

func NewUpnp() []model.ModuleMethods {
	return []model.ModuleMethods{
		&devices.UpnpDevices{},
	}
}

func NewUPNPScanner() *UpnpScanning {
	return new(UpnpScanning)
}