package os

import (
	"regexp"
	"strings"
)

type OperatingSystemData struct {
	Name    string
	Version string
}

type OperatingSystems interface {
	DetectOperating(banner string) (bool, OperatingSystemData)
}

var os []OperatingSystems = []OperatingSystems{
	Ubuntu{},
	Freebsd{},
	NetBSD{},
	Raspbian{},
	Bitvise{},
	Windows{},
	Centos{},
}

type Ubuntu struct{}
type Freebsd struct{}
type NetBSD struct{}
type Raspbian struct{}
type Bitvise struct{}
type Windows struct{}
type Centos struct{}

func (Ubuntu) DetectOperating(banner string) (ok bool, result OperatingSystemData) {
	if strings.Contains(strings.ToLower(banner), "ubuntu") {
		re := regexp.MustCompile(`ubuntu(\d+\.\d+)`)
		matches := re.FindStringSubmatch(banner)
		if len(matches) > 1 {
			result.Version = matches[1]
		}
		result.Name = "Ubuntu"
		return true, result
	}
	return false, result
}

func (Freebsd) DetectOperating(banner string) (ok bool, result OperatingSystemData) {
	if strings.Contains(strings.ToLower(banner), "freebsd") {
		re := regexp.MustCompile(`FreeBSD-(\d+)`)
		matches := re.FindStringSubmatch(banner)
		if len(matches) > 1 {
			result.Version = matches[1]
		}
		result.Name = "FreeBSD"
		return true, result
	}
	return false, result
}

func (NetBSD) DetectOperating(banner string) (ok bool, result OperatingSystemData) {
	if strings.Contains(strings.ToLower(banner), "netbsd") {
		re := regexp.MustCompile(`NetBSD_Secure_Shell-(\d+)`)
		matches := re.FindStringSubmatch(banner)
		if len(matches) > 1 {
			result.Version = matches[1]
		}
		result.Name = "NetBSD"
		return true, result
	}
	return false, result
}

func (Raspbian) DetectOperating(banner string) (ok bool, result OperatingSystemData) {
	if strings.Contains(strings.ToLower(banner), "raspbian") {
		re := regexp.MustCompile(`Raspbian-(\d+\+deb\d+u\d+)`)
		matches := re.FindStringSubmatch(banner)
		if len(matches) > 1 {
			result.Version = matches[1]
		}
		result.Name = "Raspberry Pi"
		return true, result
	}
	return false, result
}

func (Bitvise) DetectOperating(banner string) (ok bool, result OperatingSystemData) {
	if strings.Contains(strings.ToLower(banner), "bitvise") {
		re := regexp.MustCompile(`WinSSHD\)\s+([\d.]+)`)
		matches := re.FindStringSubmatch(banner)
		if len(matches) > 1 {
			result.Version = matches[1]
		}
		result.Name = "Bitvise (Windows)"
		return true, result
	}
	return false, result
}

func (Windows) DetectOperating(banner string) (ok bool, result OperatingSystemData) {
	if strings.Contains(strings.ToLower(banner), "windows") {
		re := regexp.MustCompile(`Windows_([\d.]+)`)
		matches := re.FindStringSubmatch(banner)
		if len(matches) > 1 {
			result.Version = matches[1]
		}
		result.Name = "Windows"
		return true, result
	}
	return false, result
}

func (Centos) DetectOperating(banner string) (ok bool, result OperatingSystemData) {
	if strings.Contains(strings.ToLower(banner), "centos") {
		re := regexp.MustCompile(`CentOS-(\d+)`)
		matches := re.FindStringSubmatch(banner)
		if len(matches) > 1 {
			result.Version = matches[1]
		}
		result.Name = "CentOS"
		return true, result
	}
	return false, result
}

func DetectOperatingSystems(banner string) (ok bool, result OperatingSystemData) {
	for _, v := range os {
		if ok, result = v.DetectOperating(banner); ok {
			return true, result
		}
	}
	return false, result
}
