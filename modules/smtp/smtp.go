package smtp

import (
	"strconv"
	"strings"
	"zspure/modules/model"
	devices "zspure/modules/smtp/Devices"
)

func NewSmtp() []model.ModuleMethods {
	return []model.ModuleMethods{
		&devices.SmtpDevices{},
	}
}

func NewSMTPScanner() *SmtpScanning {
	return new(SmtpScanning)
}

func VerifySMTPContents(banner string) bool {
	if len(banner) < 5 {
		return false
	}
	code, err := strconv.Atoi(banner[0:3])
	if err != nil {
		return false
	}
	lowerBanner := strings.ToLower(banner)
	switch {
	case err == nil && (code < 200 || code >= 300):
		return false
	case err == nil,
		strings.Contains(banner, "SMTP"),
		strings.Contains(lowerBanner, "blacklist"),
		strings.Contains(lowerBanner, "abuse"),
		strings.Contains(lowerBanner, "rbl"),
		strings.Contains(lowerBanner, "spamhaus"),
		strings.Contains(lowerBanner, "relay"):
		return true
	default:
		return true
	}
}
