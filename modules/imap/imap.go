package imap

import (
	"strings"
	devices "zspure/modules/imap/Devices"
	"zspure/modules/model"
)

func NewImap() []model.ModuleMethods {
	return []model.ModuleMethods{
		&devices.ImapDevices{},
	}
}

func NewImapScanner() *ImapScanning {
	return new(ImapScanning)
}

func VerifyIMAPContents(banner string) bool {
	lowerBanner := strings.ToLower(banner)
	switch {
	case strings.HasPrefix(banner, "* NO"),
		strings.HasPrefix(banner, "* BAD"):
		return false
	case strings.HasPrefix(banner, "* OK"),
		strings.HasPrefix(banner, "* PREAUTH"),
		strings.HasPrefix(banner, "* BYE"),
		strings.HasPrefix(banner, "* OKAY"),
		strings.Contains(banner, "IMAP"),
		strings.Contains(lowerBanner, "blacklist"),
		strings.Contains(lowerBanner, "abuse"),
		strings.Contains(lowerBanner, "rbl"),
		strings.Contains(lowerBanner, "spamhaus"),
		strings.Contains(lowerBanner, "relay"):
		return true
	default:
		return false
	}
}