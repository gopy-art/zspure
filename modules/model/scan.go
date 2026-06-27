package model

import (
	"net"
)

type Scan interface {
	PrintInfo()
	SetAddress(ip net.IP, port int)
	SetDetectionPacket(packet []byte)
	SetBannerPacket(packet []byte)
	ServiceDetection(conn *net.Conn) (bool, error)
	BannerGathering(conn *net.Conn) (bool, error)
	PrintResult() ScanStructure
}

type ScanStructure struct {
	IP     net.IP `json:"ip,omitempty"`
	Port   int    `json:"port,omitempty"`
	Banner string `json:"banner,omitempty"`
	Sha256 string `json:"sha_256,omitempty"`
}
