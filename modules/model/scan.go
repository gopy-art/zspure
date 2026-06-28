package model

import (
	"net"
)

type Scan interface {
	PrintInfo()
	SetDescription()
	SetAddress(ip net.IP, port int)
	SetDetectionPacket(packet []byte)
	SetBannerPacket(packet []byte)
	ServiceDetection(conn *net.Conn) (bool, error)
	BannerGathering(conn *net.Conn) (bool, error)
	PrintResult() ScanStructure
}

type ScanStructure struct {
	IP           net.IP            `json:"ip,omitempty"`
	Data         ScanDataStructure `json:"data,omitempty"`
	FingerPrints ModuleStructure   `json:"fingerprints,omitempty"`
}

type ScanDataStructure struct {
	Status    string `json:"status,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Port      int    `json:"port,omitempty"`
	Result    any    `json:"result,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}
