package imap

import (
	devices "zspure/modules/imap/Devices"
	"zspure/modules/model"
)

func NewImap() []model.ModuleMethods {
	return []model.ModuleMethods{
		&devices.ImapDevices{},
	}
}