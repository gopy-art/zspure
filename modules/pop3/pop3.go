package pop3

import (
	"strings"
	"zspure/modules/model"
	devices "zspure/modules/pop3/Devices"
)

func NewPop3() []model.ModuleMethods {
	return []model.ModuleMethods{
		&devices.Pop3Devices{},
	}
}

func NewPOP3Scanner() *Pop3Scanning {
	return new(Pop3Scanning)
}

func VerifyPOP3Contents(banner string) bool {
	lowerBanner := strings.ToLower(banner)
	switch {
	case strings.HasPrefix(banner, "-ERR "):
		return false
	case strings.HasPrefix(banner, "+OK "),
		banner == "+OK\r\n",
		strings.Contains(banner, "POP3"),
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