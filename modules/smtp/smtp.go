package smtp

import (
	devices "zspure/modules/smtp/Devices"
	"zspure/modules/model"
)

func NewSmtp() []model.ModuleMethods {
	return []model.ModuleMethods{
		&devices.SmtpDevices{},
	}
}

func NewSMTPScanner() *SmtpScanning {
	return new(SmtpScanning)
}