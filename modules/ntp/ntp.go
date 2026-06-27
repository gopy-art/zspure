package ntp

import (
	"zspure/modules/model"
	"zspure/modules/ntp/server"
)

func NewNTP() []model.ModuleMethods {
	return []model.ModuleMethods{
		&server.NTPServer{},
	}
}

func NewNTPScanner() *NtpScanning {
	return new(NtpScanning)
}
