package mssql

import (
	"fmt"
	"net"
	"zspure/modules/model"
)

type MssqlScanning struct {
	IP     net.IP `json:"ip,omitempty"`
	Port   int    `json:"port,omitempty"`
	Status string    `json:"status,omitempty"`
	Banner string `json:"banner,omitempty"`
	Sha256 string `json:"sha_256,omitempty"`

	Description     string `json:"description,omitempty"`
	DetectionPacket []byte `json:"detection_packet,omitempty"`
	BannerPacket    []byte `json:"banner_packet,omitempty"`
}

func (m *MssqlScanning) PrintInfo() {
	fmt.Println(m.Description)
}

func (m *MssqlScanning) SetDescription() {
	m.Description = "The primary application-layer protocol used by Microsoft SQL Server for client-server communication is the Tabular Data Stream (TDS) protocol."
}

func (m *MssqlScanning) SetAddress(ip net.IP, port int)                {}
func (m *MssqlScanning) SetDetectionPacket(packet []byte)              {}
func (m *MssqlScanning) SetBannerPacket(packet []byte)                 {}
func (m *MssqlScanning) ServiceDetection(conn *net.Conn) (bool, error) { return false, nil }
func (m *MssqlScanning) BannerGathering(conn *net.Conn) (bool, error)  { return false, nil }
func (m *MssqlScanning) PrintResult() model.ScanStructure              { return model.ScanStructure{} }