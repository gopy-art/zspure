package fox

import (
	devices "zspure/modules/fox/Devices"
	qnx "zspure/modules/fox/qnx"
	"zspure/modules/model"
)

func NewFox() []model.ModuleMethods {
	return []model.ModuleMethods{
		&devices.FoxDevices{},
		&qnx.FoxQnx{},
	}
}