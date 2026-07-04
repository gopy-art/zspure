package pop3

import (
	devices "zspure/modules/pop3/Devices"
	"zspure/modules/model"
)

func NewPop3() []model.ModuleMethods {
	return []model.ModuleMethods{
		&devices.Pop3Devices{},
	}
}